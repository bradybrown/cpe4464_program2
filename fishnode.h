#include <time.h>

/* Arp Entry is a node in a Arp Table linked list

    It contains the mapped <l2, l3> addrs,
    the event handle for cancelling the timeout timer,
    and the next node in the linked list.
*/
typedef struct Arp_Entry {
    fn_l2addr_t l2addr;
    fnaddr_t l3addr;
    event handle;
    struct Arp_Entry *next_entry;
} Arp_Entry;


void my_arp_resolution_cb(fn_l2addr_t resolved_l2_addr, void *param);

// Full functionality
void arp_entry_expired(void *arg);
