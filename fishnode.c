#include "fish.h"
#include <assert.h>
#include <signal.h>
#include <string.h>
#include "smartalloc.h"

#define DEBUG

// Set this to use my functions instead of the library functions
#define L2_IMPL


static int noprompt = 0;

void sigint_handler(int sig)
{
   if (SIGINT == sig)
	   fish_main_exit();
}

static int print_route(void *callback_data __attribute__((unused)),
      fnaddr_t dest, int prefix_len __attribute((unused)),
      fnaddr_t net_hop __attribute((unused)),
      int metric __attribute((unused)),
      void *entry_data __attribute__((unused))) {
   printf("%s\n", fn_ntoa(dest));
   return 0;
}

static void keyboard_callback(char *line)
{
   if (0 == strcasecmp("show neighbors", line))
      fish_print_neighbor_table();
   else if (0 == strcasecmp("show arp", line))
      fish_print_arp_table();
   else if (0 == strcasecmp("show route", line)) {
      fish_print_forwarding_table();
      fish_fwd.iterate_entries(&print_route, NULL, FISH_FWD_TYPE_BROADCAST);
   }
   else if (0 == strcasecmp("show dv", line))
      fish_print_dv_state();
   else if (0 == strcasecmp("quit", line) || 0 == strcasecmp("exit", line))
      fish_main_exit();
   else if (0 == strcasecmp("show topo", line))
      fish_print_lsa_topo();
   else if (0 == strcasecmp("help", line) || 0 == strcasecmp("?", line)) {
      printf("Available commands are:\n"
             "    exit                         Quit the fishnode\n"
             "    help                         Display this message\n"
             "    quit                         Quit the fishnode\n"
             "    show arp                     Display the ARP table\n"
             "    show dv                      Display the dv routing state\n"
             "    show neighbors               Display the neighbor table\n"
             "    show route                   Display the forwarding table\n"
             "    show topo                    Display the link-state routing\n"
             "                                 algorithm's view of the network\n"
             "                                 topology\n"
             "    ?                            Display this message\n"
            );
   }
   else if (line[0] != 0)
      printf("Type 'help' or '?' for a list of available commands.  "
             "Unknown command: %s\n", line);

   if (!noprompt)
      printf("> ");

   fflush(stdout);
}

void my_arp_resolution_cb(fn_l2addr_t resolved_l2_addr, void *param) {
   uint8_t *l2_frame_buffer = (uint8_t *)param;

   if (!FNL2_VALID(resolved_l2_addr)) {
      free(l2_frame_buffer);
      return;
   }

   // Successful ARP: Added dst l2 addr to l2 header
   memcpy(l2_frame_buffer, &resolved_l2_addr, sizeof(resolved_l2_addr));


   uint16_t packet_len = l2_frame_buffer[14] << 8 | l2_frame_buffer[15];

   // Calculate checksum: place it in the header after dst and src addrs
   uint8_t zeroedBytes[2] = {0, 0};
   uint8_t *checksum_ptr = l2_frame_buffer + 12;
   memcpy(checksum_ptr, zeroedBytes, sizeof(zeroedBytes));

   uint16_t checksum = in_cksum(l2_frame_buffer, packet_len);
   memcpy(checksum_ptr, &checksum, sizeof(checksum));

   // Send l2_frame_buffer using fish_l1_send()
   fish_l1_send(l2_frame_buffer);

   // Free l2 frame since we moved on and already made and sent the l1 frame above
   free(l2_frame_buffer);
}

// Prototypes for program 2.  Taken directly from fish.h header file
#ifdef L2_IMPL

int my_fish_l2_send(void *l3frame, fnaddr_t next_hop, int len, uint8_t l2_proto)
{
   
   // Construct L2 header to the frame. 17 + length of bytes
   // Need to allocate memory for the entire packet (with the new header) now
   uint8_t *l2_frame_buffer = (uint8_t *)smartalloc((unsigned long) (17 + len), "fishnode.c", 107, 0);

   memcpy((l2_frame_buffer + 17), (uint8_t *)l3frame, (size_t)len);  

   // Fill in the L2 fields that are already known: src L2 addr, 
   fn_l2addr_t l2_src_addr = fish_getl2address();
   memcpy(l2_frame_buffer + 6, &l2_src_addr, sizeof(l2_src_addr)); 
   
   // Add the length of the entire L2 frame
   uint16_t packet_len = htons(len + 17);
   memcpy(l2_frame_buffer + 14, &packet_len, sizeof(packet_len));

   // Add L2 protocol  
   l2_frame_buffer[16]= l2_proto;


   fish_arp.resolve_fnaddr(next_hop, my_arp_resolution_cb, l2_frame_buffer);
   /* Two Paths after we call resolve_fnaddr()

   - Cache hit:
      Returns after ~ 1ms
      Calls Callback

   - Cache Miss:
      Could take until 10s (timeout) or anytime less using ARP to find the addr.
      WONT CALL CALLBACK: Don't wait for return, once resolve_fnaddr() returns, 
                          we should return our l2_send() function.
   */

   return 0;
}

int my_fishnode_l2_receive(void *l2frame)
{
   uint8_t *l2packet = (uint8_t *)l2frame;
   uint16_t l2_frame_length = l2packet[14] << 8 | l2packet[15];   
   
   // If packet length invalid, drop this packet: don't pass it through by calling l3 receive
   if (l2_frame_length < 17 || l2_frame_length > MTU) {return 0;}
   
   // Checksum invalid, drop this packet
   if (in_cksum(l2frame, l2_frame_length)) {return 0;}

   // Ensure the L2 dest addr matches the addr of this node
   fn_l2addr_t node_addr = fish_getl2address(); 
   fn_l2addr_t dest_addr;
   memcpy(&dest_addr, l2packet, 6);
   if (!FNL2_EQ(node_addr, dest_addr) &&
       !FNL2_EQ(ALL_L2_NEIGHBORS, dest_addr)) {return 0;}


   // Decapsulate
   uint8_t *l3packet = l2packet + 17;
   uint8_t protocol = l2packet[16];

   switch (protocol) {
      case 1:  // L3 Protocol
         fish_l3.fish_l3_receive(l3packet, l2_frame_length - 17, protocol);
         break;
      case 2:  // ARP Protocol
         fish_arp.arp_received(l2frame);
         break;
      default: // Unknown protocol, drop packet 
         break;
   }

   return 0;
}

void my_arp_received(void *l2frame)
{
}

void my_send_arp_request(fnaddr_t l3addr)
{
}

// Full functionality
void my_add_arp_entry(fn_l2addr_t l2addr, fnaddr_t addr, int timeout)
{
}

void my_resolve_fnaddr(fnaddr_t addr, arp_resolution_cb cb, void *param)
{
}
#endif

#ifdef L3_IMPL
int my_fishnode_l3_receive(void *l3frame, int len)
{
   return 0;
}

int my_fish_l3_send(void *l4frame, int len, fnaddr_t dst_addr,
               uint8_t proto, uint8_t ttl)
{
   return 0;
}

int my_fish_l3_forward(void *l3frame, int len)
{
   return 0;
}

// Callback to broadcast DV advertisement
void my_timed_event(void*)
{
}

// Full functionality
void* my_add_fwtable_entry(fnaddr_t dst, int prefix_length, fnaddr_t next_hop,
                   int metric, char type, void *user_data)
{
   return NULL;
}

void* my_remove_fwtable_entry(void *route_key)
{
   return NULL;
}

int my_update_fwtable_metric(void *route_key, int new_metric)
{
   return 0;
}

fnaddr_t my_longest_prefix_match(fnaddr_t addr)
{
   return 0;
}
#endif

int main(int argc, char **argv)
{
	struct sigaction sa;
   int arg_offset = 1;

   /* Verify and parse the command line parameters */
	if (argc != 2 && argc != 3 && argc != 4)
	{
		printf("Usage: %s [-noprompt] <fishhead address> [<fn address>]\n", argv[0]);
		return 1;
	}

   if (0 == strcasecmp(argv[arg_offset], "-noprompt")) {
      noprompt = 1;
      arg_offset++;
   }

   /* Install the signal handler */
	sa.sa_handler = sigint_handler;
	sigfillset(&sa.sa_mask);
	sa.sa_flags = 0;
	if (-1 == sigaction(SIGINT, &sa, NULL))
	{
		perror("Couldn't set signal handler for SIGINT");
		return 2;
	}

   /* Set up debugging output */
#ifdef DEBUG
	fish_setdebuglevel(FISH_DEBUG_INTERNAL);
	// fish_setdebuglevel(FISH_DEBUG_ALL);
#else
	fish_setdebuglevel(FISH_DEBUG_NONE);
#endif
	fish_setdebugfile(stdout);

   /* Join the fishnet */
	if (argc-arg_offset == 1)
		fish_joinnetwork(argv[arg_offset]);
	else
		fish_joinnetwork_addr(argv[arg_offset], fn_aton(argv[arg_offset+1]));

   /* Install the command line parsing callback */
   fish_keybhook(keyboard_callback);
   if (!noprompt)
      printf("> ");
   fflush(stdout);

#ifdef L2_IMPL
   // Examples of overriding function pointers for program 2 base functionality
   // fish_l2.fishnode_l2_receive = &my_fishnode_l2_receive;
   fish_l2.fish_l2_send = &my_fish_l2_send;
   // fish_arp.arp_received = &my_arp_received;
   // fish_arp.send_arp_request = &my_send_arp_request;
   // // Full functionality functions
   // fish_arp.add_arp_entry = &my_add_arp_entry;
   // fish_arp.resolve_fnaddr = &my_resolve_fnaddr;
#endif

#ifdef L3_IMPL
   fish_l3.fishnode_l3_receive = &my_fishnode_l3_receive;
   fish_l3.fish_l3_send = &my_fish_l3_send;
   fish_l3.fish_l3_forward = &my_fish_l3_forward;
   // Set up a callback to broadcast DV advertisement
   fish_scheduleevent(0, &my_timed_event, NULL);
   // Full functionality
   fish_fwd.add_fwtable_entry = &my_add_fwtable_entry;
   fish_fwd.remove_fwtable_entry = &my_remove_fwtable_entry;
   fish_fwd.update_fwtable_metric = &my_update_fwtable_metric;
   fish_fwd.longest_prefix_match = &my_longest_prefix_match;
#endif

#if 1
   /* Enable the built-in neighbor protocol implementation.  This will discover
    * one-hop routes in your fishnet.  The link-state routing protocol requires
    * the neighbor protocol to be working, whereas it is redundant with DV.
    * Running them both doesn't break the fishnode, but will cause extra routing
    * overhead */
   fish_enable_neighbor_builtin( 0
         | NEIGHBOR_USE_LIBFISH_NEIGHBOR_DOWN
      );
#endif

   /* Enable the link-state routing protocol.  This requires the neighbor
    * protocol to be enabled. */
   // fish_enable_lsarouting_builtin(0);

// TODO: Change back to 0 once done with testing
#if 1 
   /* Full-featured DV routing.  I suggest NOT using this until you have some
    * reasonable expectation that your code works.  This generates a lot of
    * routing traffic in fishnet */

   fish_enable_dvrouting_builtin( 0
         | DVROUTING_WITHDRAW_ROUTES
         | DVROUTING_TRIGGERED_UPDATES
         | RVROUTING_USE_LIBFISH_NEIGHBOR_DOWN
         | DVROUTING_SPLIT_HOR_POISON_REV
         | DVROUTING_KEEP_ROUTE_HISTORY
    );
#endif





   /* Execute the libfish event loop */
	fish_main();

   /* Clean up and exit */
   if (!noprompt)
      printf("\n");
   fish_keybhook(NULL);

	printf("Fishnode exiting cleanly.\n");

   fishnet_cleanup();

   // Cleanup your data structures here

	return 0;
}
