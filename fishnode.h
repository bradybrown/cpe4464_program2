
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

/* This is a node in the linked list of packets that are queued up.

    These packets are waiting for and ARP to be resolved so that they 
    know where to send these packets. They contain the callback (and 
    the argument "param") which they will call once ready.
*/
typedef struct Pending_Packet {
    arp_resolution_cb cb;
    void *param;
    struct Pending_Packet *next_packet;
} Pending_Packet;


/*  This is a node in the linked list of pending ARPs to be resolved. 
    
    Each of these ARPs contain a linked list of the Pending Packets 
    so it can either be NULL or contain a node which points to the 
    rest of the nodes in the list. 
*/
typedef struct Pending_ARP {
    fnaddr_t l3addr;
    int requests_sent;
    event timer;
    Pending_Packet *waiting;
    struct Pending_ARP *next_arp;
} Pending_ARP;


void my_arp_resolution_cb(fn_l2addr_t resolved_l2_addr, void *param);

// Full functionality
void arp_entry_expired(void *arg);
void arp_retry(void *arg);
