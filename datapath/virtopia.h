/*
 * Copyright (c) 2007-2017 Nicira, Inc.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of version 2 of the GNU General Public
 * License as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt


#include <linux/kernel.h>
#include <linux/hashtable.h>
#include <linux/cryptohash.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <net/mptcp.h> // must be MPTCP Linux kernel 
#include <net/tcp.h>  //must be MPTCP Linux kernel



/* MPTCP Kernel required */
extern void tcp_parse_mptcp_options(const struct sk_buff *skb,
                 struct mptcp_options_received *mopt);
extern void mptcp_key_sha1(u64 key, u32 *token, u64 *idsn);


/* Hashtable lock */
static DEFINE_SPINLOCK(datalock);
static DEFINE_SPINLOCK(acklock);
static DEFINE_SPINLOCK(tokenlock);

/*TODO for production code, use resizable hashtable
A technique related to IBM, https://lwn.net/Articles/612021/
*/
/* Hashtable */
#define TBL_SIZE 15U
static DEFINE_HASHTABLE(rcv_data_hashtbl, TBL_SIZE);
static DEFINE_HASHTABLE(rcv_ack_hashtbl, TBL_SIZE);
static DEFINE_HASHTABLE(token_key_hashtbl, TBL_SIZE);

#define BRIDGE_NAME "ovsbr*"

struct rcv_data {
    u64 key; //key of a flow, {LOW16(srcip), LOW16(dstip), tcpsrc, tcpdst}
    u32 ecn_bytes_per_ack; //32 bit should be sufficient
    u32 total_bytes_per_ack; //32 bit should be sufficient
    spinlock_t lock; //lock for read/write, write/write conflicts
    struct hlist_node hash;
    struct rcu_head rcu;
};

struct rcv_ack {
    u64 key;
    u32 rwnd;
    u32 rwnd_ssthresh;
    u32 rwnd_clamp;
    u32 alpha;
    u32 snd_una;
    u32 snd_nxt;
    u32 next_seq;
    u8 snd_wscale;
    u32 snd_rwnd_cnt;
    u16 prior_real_rcv_wnd;
    u32 dupack_cnt;
    bool loss_detected_this_win;
    bool reduced_this_win;
    u32 ecn_bytes;
    u32 total_bytes;
    spinlock_t lock;
    struct hlist_node hash;
    struct rcu_head rcu;

    u64 receiver_key;
    u32 remote_token; 
    u64 peer_subflow_key;

};

struct token_key {
    u32 token; //this is the actual key in token_key_hashtb;
    u64 tcp_key64;    // master sk tcp_key64 calculated by get_tcp_key64(4 tuple)
    u32 srcip; // master sk srcip
    u32 dstip; // master sk dstip
    u16 srcport; // master sk srcport
    u16 dstport; // master sk dstprot
    spinlock_t lock;
    struct hlist_node hash;
    struct rcu_head rcu;
};



/* test function for virtopia */

void virtopia_test(void);


/* Hashtable usage for virtopia */
/* rcv_data_hashtbl functions*/

static u16 ovs_hash_min(u64 key, int size) {
    u16 low16;
    u32 low32;

    low16 = key & ((1UL << 16) - 1);
    low32 = key & ((1UL << 32) - 1);

    low32 = low32 >> 16;
    return (low16 + low32) % (1 << size);
}

//insert a new entry
static void rcv_data_hashtbl_insert(u64 key, struct rcv_data *value)
{
    u32 bucket_hash;
    bucket_hash = ovs_hash_min(key, HASH_BITS(rcv_data_hashtbl)); //hash_min is the same as hash_long if key is 64bit
    //lock the table
    spin_lock(&datalock);
    hlist_add_head_rcu(&value->hash, &rcv_data_hashtbl[bucket_hash]);
    spin_unlock(&datalock);
}

static void free_rcv_data_rcu(struct rcu_head *rp)
{
    struct rcv_data * tofree = container_of(rp, struct rcv_data, rcu);
    kfree(tofree);
}

static void rcv_data_hashtbl_delete(struct rcv_data *value)
{
    //lock the table
    spin_lock(&datalock);
    hlist_del_init_rcu(&value->hash);
    spin_unlock(&datalock);
    call_rcu(&value->rcu, free_rcv_data_rcu);
}

//caller must use "rcu_read_lock()" to guard it
static struct rcv_data * rcv_data_hashtbl_lookup(u64 key)
{
    int j = 0;
    struct rcv_data * v_iter = NULL;


    j = ovs_hash_min(key, HASH_BITS(rcv_data_hashtbl));
    hlist_for_each_entry_rcu(v_iter, &rcv_data_hashtbl[j], hash)
    if (v_iter->key == key) /* iterm found*/
        return v_iter;
    return NULL; /*return NULL if can not find it */
}

//delete all entries in the hashtable
static void rcv_data_hashtbl_destroy(void)
{
    struct rcv_data * v_iter;
    struct hlist_node * tmp;
    int j = 0;

    rcu_barrier(); //wait until all rcu_call are finished

    spin_lock(&datalock); //no new insertion or deletion !
    hash_for_each_safe(rcv_data_hashtbl, j, tmp, v_iter, hash) {
        hash_del(&v_iter->hash);
        kfree(v_iter);
        pr_info("delete one entry from rcv_data_hashtbl table\n");
    }
    spin_unlock(&datalock);
}

/*functions for rcv_ack_hashtbl*/
//insert a new entru
static void rcv_ack_hashtbl_insert(u64 key, struct rcv_ack *value)
{
    u32 bucket_hash;
    bucket_hash = ovs_hash_min(key, HASH_BITS(rcv_ack_hashtbl)); //hash_min is the same as hash_long if key is 64bit
    //lock the table
    spin_lock(&acklock);
    hlist_add_head_rcu(&value->hash, &rcv_ack_hashtbl[bucket_hash]);
    spin_unlock(&acklock);
}

static void free_rcv_ack_rcu(struct rcu_head *rp)
{
    struct rcv_ack * tofree = container_of(rp, struct rcv_ack, rcu);
    kfree(tofree);
}

static void rcv_ack_hashtbl_delete(struct rcv_ack *value)
{
    //lock the table
    spin_lock(&acklock);
    hlist_del_init_rcu(&value->hash);
    spin_unlock(&acklock);
    call_rcu(&value->rcu, free_rcv_ack_rcu);
}

//caller must use "rcu_read_lock()" to guard it
static struct rcv_ack * rcv_ack_hashtbl_lookup(u64 key)
{
    int j = 0;
    struct rcv_ack * v_iter = NULL;


    j = ovs_hash_min(key, HASH_BITS(rcv_ack_hashtbl));
    hlist_for_each_entry_rcu(v_iter, &rcv_ack_hashtbl[j], hash)
    if (v_iter->key == key) /* iterm found*/
        return v_iter;
    return NULL; /*return NULL if can not find it */
}

//delete all entries in the hashtable
static void rcv_ack_hashtbl_destroy(void)
{
    struct rcv_ack * v_iter;
    struct hlist_node * tmp;
    int j = 0;

    rcu_barrier(); //wait until all rcu_call are finished

    spin_lock(&acklock); //no new insertion or deletion !
    hash_for_each_safe(rcv_ack_hashtbl, j, tmp, v_iter, hash) {
        hash_del(&v_iter->hash);
        kfree(v_iter);
        pr_info("delete one entry from rcv_ack_hashtbl table\n");
    }
    spin_unlock(&acklock);
}



/*functions for rcv_ack_hashtbl*/
//insert a new entry
static void token_key_hashtbl_insert(u32 token, struct token_key *value)
{
    u32 bucket_hash;
    bucket_hash = ovs_hash_min((u64)token, HASH_BITS(token_key_hashtbl)); //hash_min is the same as hash_long if key is 64bit
    //lock the table
    spin_lock(&tokenlock);
    hlist_add_head_rcu(&value->hash, &token_key_hashtbl[bucket_hash]);
    spin_unlock(&tokenlock);
}

static void free_token_key_rcu(struct rcu_head *rp)
{
    struct token_key * tofree = container_of(rp, struct token_key, rcu);
    kfree(tofree);
}

static void token_key_hashtbl_delete(struct token_key *value)
{
    //lock the table
    spin_lock(&tokenlock);
    hlist_del_init_rcu(&value->hash);
    spin_unlock(&tokenlock);
    call_rcu(&value->rcu, free_token_key_rcu);
}

//caller must use "rcu_read_lock()" to guard it
static struct token_key * token_key_hashtbl_lookup(u32 token)
{
    int j = 0;
    struct token_key * v_iter = NULL;


    j = ovs_hash_min((u64)token, HASH_BITS(token_key_hashtbl));
    hlist_for_each_entry_rcu(v_iter, &token_key_hashtbl[j], hash)
    if (v_iter->token == token) /* iterm found*/
        return v_iter;
    return NULL; /*return NULL if can not find it */
}

//delete all entries in the hashtable
static void token_key_hashtbl_destroy(void)
{
    struct token_key * v_iter;
    struct hlist_node * tmp;
    int j = 0;

    rcu_barrier(); //wait until all rcu_call are finished

    spin_lock(&tokenlock); //no new insertion or deletion !
    hash_for_each_safe(token_key_hashtbl, j, tmp, v_iter, hash) {
        hash_del(&v_iter->hash);
        kfree(v_iter);
        pr_info("delete one entry from token_key_hashtbl table\n");
    }
    spin_unlock(&tokenlock);
}


//clear the 3 hash tables we added, used in module exit function
static void __hashtbl_exit(void) {
    rcv_data_hashtbl_destroy();
    rcv_ack_hashtbl_destroy();
    token_key_hashtbl_destroy();
}



//rcv_data, rcv_ack, token_key hash table tests*/
static void __hashtable_test(void) {
    u64 i;
    u64 j;
    struct timeval tstart;
    struct timeval tend;

    printk(KERN_INFO "start hashtbl tests.\n");

    /*rcv_data_hashtbl performance*/
    do_gettimeofday(&tstart);
    for (i = 0; i < (1 << TBL_SIZE); i ++) {
        struct rcv_data * value = NULL;
        value = kzalloc(sizeof(*value), GFP_KERNEL);
        value->key = i;
        rcv_data_hashtbl_insert(i, value);
    }

    do_gettimeofday(&tend);
    printk("rcv_data_hashtbl insert time taken: %ld microseconds\n", 1000000 * (tend.tv_sec - tstart.tv_sec) +
           (tend.tv_usec - tstart.tv_usec) );


    do_gettimeofday(&tstart);
    for (i = 0; i < (1 << TBL_SIZE); i ++) {
        for (j = 0; j < (1 << TBL_SIZE); j ++) {
            struct rcv_data * value = NULL;
            rcu_read_lock();
            value = rcv_data_hashtbl_lookup(j);
            rcu_read_unlock();
        }
    }
    do_gettimeofday(&tend);
    printk("rcv_data_hashtbl lookup time taken: %ld microseconds\n", 1000000 * (tend.tv_sec - tstart.tv_sec) +
           (tend.tv_usec - tstart.tv_usec) );


    for (i = 0; i < (1 << TBL_SIZE); i ++) {
        struct rcv_data * value = NULL;
        rcu_read_lock();
        value = rcv_data_hashtbl_lookup(i);
        if (value)
            ;
        //printk("lookup okay, value->key:%lu\n", value->key);
        else
            printk("rcv_data_hashtbl lookup bad!\n");
        rcu_read_unlock();
    }


    do_gettimeofday(&tstart);
    for (i = 0; i < (1 << TBL_SIZE); i ++) {
        struct rcv_data * value = NULL;
        rcu_read_lock();
        value = rcv_data_hashtbl_lookup(i);
        rcu_read_unlock();
        rcv_data_hashtbl_delete(value);
    }
    do_gettimeofday(&tend);
    printk("rcv_data_hashtbl deletion time taken: %ld microseconds\n", 1000000 * (tend.tv_sec - tstart.tv_sec) +
           (tend.tv_usec - tstart.tv_usec) );



    /*rcv_ack_hashtbl performance*/
    do_gettimeofday(&tstart);
    for (i = 0; i < (1 << TBL_SIZE); i ++) {
        struct rcv_ack * value = NULL;
        value = kzalloc(sizeof(*value), GFP_KERNEL);
        value->key = i;
        rcv_ack_hashtbl_insert(i, value);
    }

    do_gettimeofday(&tend);
    printk("rcv_ack_hashtbl insert time taken: %ld microseconds\n", 1000000 * (tend.tv_sec - tstart.tv_sec) +
           (tend.tv_usec - tstart.tv_usec) );

    //Lookup performance
    do_gettimeofday(&tstart);
    for (i = 0; i < (1 << TBL_SIZE); i ++) {
        for (j = 0; j < (1 << TBL_SIZE); j ++) {
            struct rcv_ack * value = NULL;
            rcu_read_lock();
            value = rcv_ack_hashtbl_lookup(j);
            rcu_read_unlock();
        }
    }
    do_gettimeofday(&tend);
    printk("rcv_ack_hashtbl lookup time taken: %ld microseconds\n", 1000000 * (tend.tv_sec - tstart.tv_sec) +
           (tend.tv_usec - tstart.tv_usec) );

    //correctness check of lookup
    for (i = 0; i < (1 << TBL_SIZE); i ++) {
        struct rcv_ack * value = NULL;
        rcu_read_lock();
        value = rcv_ack_hashtbl_lookup(i);
        if (value)
            ;
        //printk("lookup okay, value->key:%lu\n", value->key);
        else
            printk("rcv_ack_hashtbl lookup bad!\n");
        rcu_read_unlock();
    }

    //delete performacne
    do_gettimeofday(&tstart);
    for (i = 0; i < (1 << TBL_SIZE); i ++) {
        struct rcv_ack * value = NULL;
        rcu_read_lock();
        value = rcv_ack_hashtbl_lookup(i);
        rcu_read_unlock();
        rcv_ack_hashtbl_delete(value);
    }
    do_gettimeofday(&tend);
    printk("rcv_ack_hashtbl deletion time taken: %ld microseconds\n", 1000000 * (tend.tv_sec - tstart.tv_sec) +
           (tend.tv_usec - tstart.tv_usec) );


    
    /*token_key_hashtbl performance*/
    do_gettimeofday(&tstart);
    for (i = 0; i < (1 << TBL_SIZE); i ++) {
        struct token_key * value = NULL;
        value = kzalloc(sizeof(*value), GFP_KERNEL);
        value->token = i;
        token_key_hashtbl_insert(i, value);
    }

    do_gettimeofday(&tend);
    printk("token_key_hashtbl insert time taken: %ld microseconds\n", 1000000 * (tend.tv_sec - tstart.tv_sec) +
           (tend.tv_usec - tstart.tv_usec) );

    //Lookup performance
    do_gettimeofday(&tstart);
    for (i = 0; i < (1 << TBL_SIZE); i ++) {
        for (j = 0; j < (1 << TBL_SIZE); j ++) {
            struct token_key * value = NULL;
            rcu_read_lock();
            value = token_key_hashtbl_lookup(j);
            rcu_read_unlock();
        }
    }
    do_gettimeofday(&tend);
    printk("token_key_hashtbl lookup time taken: %ld microseconds\n", 1000000 * (tend.tv_sec - tstart.tv_sec) +
           (tend.tv_usec - tstart.tv_usec) );

    //correctness check of lookup
    for (i = 0; i < (1 << TBL_SIZE); i ++) {
        struct token_key * value = NULL;
        rcu_read_lock();
        value = token_key_hashtbl_lookup(i);
        if (value)
            ;
        //printk("lookup okay, value->key:%lu\n", value->key);
        else
            printk("token_key_hashtbl lookup bad!\n");
        rcu_read_unlock();
    }

    //delete performacne
    do_gettimeofday(&tstart);
    for (i = 0; i < (1 << TBL_SIZE); i ++) {
        struct token_key * value = NULL;
        rcu_read_lock();
        value = token_key_hashtbl_lookup(i);
        rcu_read_unlock();
        token_key_hashtbl_delete(value);
    }
    do_gettimeofday(&tend);
    printk("token_key_hashtbl deletion time taken: %ld microseconds\n", 1000000 * (tend.tv_sec - tstart.tv_sec) +
           (tend.tv_usec - tstart.tv_usec) );



    printk(KERN_INFO "end hashtbl tests.\n");
}



/*help function get a u64 key for a TCP flow */
static u64 get_tcp_key64(u32 ip1, u32 ip2, u16 tp1, u16 tp2) {
    u64 key = 0;
    u64 part1, part2, part3, part4;

    part1 = ip1 & ((1 << 16) - 1); // get the lower 16 bits of u32
    part1 = part1 << 48; //the highest 16 bits of the result

    part2 = ip2 & ((1 << 16) - 1);
    part2 = part2 << 32;

    part3 = tp1 << 16;

    part4 = tp2;

    key = part1 + part2 + part3 + part4;
    return key;

}

/*helper function, determine the direction of the traffic (packet), i.e., go to the net or come to the host?*/
static bool ovs_packet_to_net(struct sk_buff *skb) {
    if (strncmp(skb->dev->name, BRIDGE_NAME, 5) == 0 )
        return 1;
    else
        return 0;
}


/*extract window scaling factor, Normally only called on SYN and SYNACK packets.
see http://packetlife.net/blog/2010/aug/4/tcp-windows-and-window-scaling/
TODO: we do not consider the case that one side uses scaling while the other does
not support it (in this case, both should not use scaling factor).
This should be handled in production code
*/

static u8 ovs_tcp_parse_options(const struct sk_buff *skb) {
    u8 snd_wscale = 0;

    const unsigned char *ptr;
    const struct tcphdr *th = tcp_hdr(skb);
    int length = (th->doff * 4) - sizeof(struct tcphdr);

    ptr = (const unsigned char *)(th + 1);

    while (length > 0) {
        int opcode = *ptr++;
        int opsize;
        switch (opcode) {
        case TCPOPT_EOL:
            return 0;
        case TCPOPT_NOP:        /* Ref: RFC 793 section 3.1 */
            length--;
            continue;
        default:
            opsize = *ptr++;
            if (opsize < 2) /* "silly options" */
                return 0;
            if (opsize > length)
                return 0; /* don't parse partial options */
            switch (opcode) {
            case TCPOPT_WINDOW:
                if (opsize == TCPOLEN_WINDOW && th->syn) {
                    snd_wscale = *(__u8 *)ptr;
                    if (snd_wscale > 14) {
                        printk("Illegal window scaling: %u\n", snd_wscale);
                        snd_wscale = 14;
                    }
                }
                break;
            default:
                break;
            }
            ptr += opsize - 2;
            length -= opsize;
        }
    }
    return snd_wscale;
}




void virtopia_proc_syn(struct sk_buff *skb, struct iphdr *nh, struct tcphdr *tcp);


void virtopia_proc_ack(struct sk_buff *skb);

void virtopia_proc_fin(struct sk_buff *skb, struct iphdr *nh, struct tcphdr *tcp);