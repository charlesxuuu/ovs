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

#include "virtopia.h"


#define MSS_DEFAULT (1500U - 14U - 20U -20U)  //in bytes
static unsigned int MSS = MSS_DEFAULT;
module_param(MSS, uint, 0644);
MODULE_PARM_DESC(MSS, "An unsigned int to initlize the MSS");


#define RWND_INIT 10U*MSS
#define RWND_CLAMP (10*1000*1000*4/8) //4 means the maximal latency expected (4 msec), in bytes
#define RWND_MIN MSS
#define RWND_SSTHRESH_INIT (RWND_CLAMP >> 1)
#define DCTCP_ALPHA_INIT 1024U

#define IPERF_DEBUG 1

/* test function for virtopia */

void virtopia_test(void)
{
	printk("virtopia_test");
} 

/* test extern function for virtopia */

void virtopia_extern_test(void)
{
	printk("virtopia_extern_test");
} 

void virtopia_init_rcv_ack(struct rcv_ack *new_entry, struct tcphdr *tcp) 
{
	new_entry->rwnd = RWND_INIT;
    new_entry->rwnd_ssthresh = RWND_SSTHRESH_INIT;
    new_entry->rwnd_clamp = RWND_CLAMP;
    new_entry->alpha = DCTCP_ALPHA_INIT;
    new_entry->snd_una = ntohl(tcp->seq);
    new_entry->snd_nxt = ntohl(tcp->seq) + 1; //SYN takes 1 byte
    new_entry->next_seq = new_entry->snd_nxt;
    //SIGCOMM, Sep 19, 2015, Window Scaling factor logic was wrong
    //new_entry->snd_wscale = ovs_tcp_parse_options(skb);
    new_entry->snd_rwnd_cnt = 0;
    new_entry->reduced_this_win = false;
    new_entry->loss_detected_this_win = false;
    new_entry->prior_real_rcv_wnd = ntohs(tcp->window);
    new_entry->dupack_cnt = 0;
    new_entry->ecn_bytes = 0;
    new_entry->total_bytes = 0;

    new_entry->receiver_key=0;
    new_entry->remote_token=0; 
    new_entry->peer_subflow_key=0;
}

/*
 * Process SYN packet
 * TCP_SYN / MPTCP_SYN_INI / MPTCP_SYN_JOIN
 */
void virtopia_proc_syn(struct sk_buff *skb, struct iphdr *nh, struct tcphdr *tcp) 
{
	//TCP_SYN or MPTCP_SYN
    u32 srcip;
    u32 dstip;
    u16 srcport;
    u16 dstport;
    u64 tcp_key64;

    srcip = ntohl(nh->saddr);
    dstip = ntohl(nh->daddr);
    srcport = ntohs(tcp->source);
    dstport = ntohs(tcp->dest);

    struct rcv_ack *new_entry;
    new_entry = NULL;

    tcp_key64 = get_tcp_key64(dstip, srcip, dstport, srcport);
	rcu_read_lock();
    new_entry = rcv_ack_hashtbl_lookup(tcp_key64);
	rcu_read_unlock();

    if (likely(!new_entry)) {
        new_entry = kzalloc(sizeof(*new_entry), GFP_KERNEL);
        new_entry->key = tcp_key64;
        rcv_ack_hashtbl_insert(tcp_key64, new_entry);
    }

    virtopia_init_rcv_ack(new_entry, tcp);
    spin_lock_init(&new_entry->lock);


    struct mptcp_options_received mopt;
    mptcp_init_mp_opt(&mopt);
    tcp_parse_mptcp_options(skb, &mopt);

    u64 mptcp_sender_key; 
    u64 mptcp_receiver_key;
    u32 mptcp_rem_token;

    mptcp_sender_key = mopt.mptcp_sender_key;
    mptcp_receiver_key = mopt.mptcp_receiver_key;
    mptcp_rem_token = mopt.mptcp_rem_token;

	//printk(KERN_INFO "[MPTCP SYN] srcport is %d, dstport is %d, saw_mpc is %d, is_mp_join is %d, join_ack is %d, sender_key is %llu, receiver_key is %llu, token is %u", 
    //srcport, dstport, mopt.saw_mpc, mopt.is_mp_join, mopt.join_ack, mopt.mptcp_sender_key, mopt.mptcp_receiver_key, mopt.mptcp_rem_token);

    //MPTCP_SYN_INIT
    if (mopt.saw_mpc == 1 && mopt.is_mp_join == 0 && mopt.join_ack == 0) {
    	#ifdef IPERF_DEBUG
		if (dstport == 5001) { //iperf test
    		//printk(KERN_INFO "[MPTCP SYN] MPTCP_SYN_INIT, mptcp_sender_key is %llu", mptcp_sender_key);
            printk(KERN_INFO "[MPTCP SYN] MPTCP_SYN_INIT srcport is %d, dstport is %d, saw_mpc is %d, is_mp_join is %d, join_ack is %d, sender_key is %llu", 
            srcport, dstport, mopt.saw_mpc, mopt.is_mp_join, mopt.join_ack, mopt.mptcp_sender_key);
    	}
    	#endif
    }

    //MPTCP_SYN_JOIN
    if (mopt.saw_mpc == 1 && mopt.is_mp_join == 1 && mopt.join_ack == 0) {
    	#ifdef IPERF_DEBUG
		if (dstport == 5001) { //iperf test
    		//printk(KERN_INFO "[MPTCP SYN] MPTCP_SYN_JOIN, srcport is %d, dstport is %d, mptcp_rem_token is %u", srcport, dstport, mptcp_rem_token);
            printk(KERN_INFO "[MPTCP SYN] MPTCP_SYN_JOIN, srcport is %d, dstport is %d, saw_mpc is %d, is_mp_join is %d, join_ack is %d, sender_key is %llu", 
            srcport, dstport, mopt.saw_mpc, mopt.is_mp_join, mopt.join_ack, mopt.mptcp_sender_key);
    	}
    	#endif

        rcu_read_lock();  
        struct token_key *existing_token_key;
        existing_token_key = NULL;
        existing_token_key = token_key_hashtbl_lookup(mptcp_rem_token);
        rcu_read_unlock();

        if(existing_token_key) {
            struct rcv_ack *master_subflow_ack_entry = NULL;
            master_subflow_ack_entry = rcv_ack_hashtbl_lookup(existing_token_key->key);
            //key association
            if (master_subflow_ack_entry) {
                //not now, full mesh will try all possible pairs
                //master_subflow_ack_entry->peer_subflow_key = tcp_key64; 
                new_entry->peer_subflow_key = master_subflow_ack_entry->key;
            }
            master_subflow_ack_entry = NULL;
        }
        existing_token_key = NULL;
    }
    new_entry = NULL;
}


void virtopia_proc_ack(struct sk_buff *skb, struct iphdr *nh, struct tcphdr *tcp) 
{
	u32 srcip;
    u32 dstip;
    u16 srcport;
    u16 dstport;
    u64 tcp_key64;

    srcip = ntohl(nh->saddr);
    dstip = ntohl(nh->daddr);
    srcport = ntohs(tcp->source);
    dstport = ntohs(tcp->dest);

    u64 mptcp_sender_key; 
    u64 mptcp_receiver_key;
	u32 mptcp_calc_token;


    struct mptcp_options_received mopt;
    mptcp_init_mp_opt(&mopt);
    tcp_parse_mptcp_options(skb, &mopt);

    mptcp_sender_key = mopt.mptcp_sender_key;
    mptcp_receiver_key = mopt.mptcp_receiver_key;
    mptcp_calc_token = 0;
    


    if (mopt.saw_mpc == 1 && mopt.is_mp_join == 0 && mopt.join_ack == 0) {//this is an initial subflow handshake ack
        mptcp_key_sha1(mptcp_receiver_key, &mptcp_calc_token, NULL);


        #ifdef IPERF_DEBUG
        if (dstport == 5001) {
            //printk(KERN_INFO "[MPTCP ACK] srcport is %d, dstport is %d, mopt.saw_mpc is %d, is_mp_join is %d, join_ack is %d, sender_key is %llu, receiver_key is %llu, calc_token is %u", srcport, dstport, mopt.saw_mpc, mopt.is_mp_join, mopt.join_ack, sender_key, receiver_key, calc_token);
        	printk(KERN_INFO "[MPTCP HANDSHAKE ACK] receiver_key is %llu, calculated token is %u", 
        		mptcp_receiver_key, mptcp_calc_token);
        }
        #endif


        struct rcv_ack *cur_entry;
        cur_entry = NULL;
        tcp_key64 = get_tcp_key64(dstip, srcip, dstport, srcport);
        rcu_read_lock();
        cur_entry = rcv_ack_hashtbl_lookup(tcp_key64);
        rcu_read_unlock();

        if (cur_entry) {
            cur_entry->remote_token = mptcp_calc_token;
        }
        cur_entry = NULL;


    	struct token_key *new_token_key;
        new_token_key = NULL;
        rcu_read_lock();
        new_token_key = token_key_hashtbl_lookup(mptcp_calc_token);
        rcu_read_unlock();
        if (unlikely(!new_token_key)) {
            new_token_key = kzalloc(sizeof(*new_token_key), GFP_KERNEL);
            new_token_key->token = mptcp_calc_token;
            new_token_key->key = tcp_key64;
            new_token_key->srcip = srcip;
            new_token_key->dstip = dstip;
            new_token_key->srcport = srcport;
            new_token_key->dstport = dstport;
            token_key_hashtbl_insert(mptcp_calc_token, new_token_key);
        }
        new_token_key = NULL;
    }

    if (mopt.saw_mpc == 1 && mopt.is_mp_join == 0 && mopt.join_ack == 1) {
        #ifdef IPERF_DEBUG
        if (dstport == 5001) {
            printk(KERN_INFO "[MPTCP JOIN HANDSHAKE ACK]");
        }
        #endif

        //reassociate
        struct rcv_ack *cur_entry;
        cur_entry = NULL;
        tcp_key64 = get_tcp_key64(dstip, srcip, dstport, srcport);
        rcu_read_lock();
        cur_entry = rcv_ack_hashtbl_lookup(tcp_key64);
        rcu_read_unlock();


        if (cur_entry) {
            struct rcv_ack *master_subflow_ack_entry;
            master_subflow_ack_entry = NULL;
            rcu_read_lock();
            master_subflow_ack_entry = rcv_ack_hashtbl_lookup(cur_entry->peer_subflow_key);
            rcu_read_unlock();

            if (master_subflow_ack_entry) {
                master_subflow_ack_entry->peer_subflow_key = tcp_key64;
            }
            master_subflow_ack_entry = NULL;
        }
        cur_entry = NULL;
    }

    // if (mopt.saw_mpc == 0 && mopt.is_mp_join == 0 && mopt.join_ack == 0) {
    //     #ifdef IPERF_DEBUG
    //     if (dstport == 5001) {
    //         printk(KERN_INFO "[MPTCP ACK] srcport is %d, dstport is %d, saw_mpc is %d, is_mp_join is %d, join_ack is %d", 
    //         srcport, dstport, mopt.saw_mpc, mopt.is_mp_join, mopt.join_ack);
    //     }
    //     #endif

    //     virtopia_proc_data_ack(skb, nh, tcp);
    // }

}

void virtopia_proc_data_ack(struct sk_buff *skb, struct iphdr *nh, struct tcphdr *tcp) 
{
    // Do congestion control

    u32 srcip;
    u32 dstip;
    u16 srcport;
    u16 dstport;
    u64 tcp_key64;

    srcip = ntohl(nh->saddr);
    dstip = ntohl(nh->daddr);
    srcport = ntohs(tcp->source);
    dstport = ntohs(tcp->dest);

    int tcp_data_len;
    tcp_data_len = ntohs(nh->tot_len) - (nh->ihl << 2) - (tcp->doff << 2);

    struct rcv_ack *ack_entry;
    ack_entry = NULL;
    tcp_key64 = get_tcp_key64(dstip, srcip, dstport, srcport);
    u32 acked = 0;
    rcu_read_lock();
    ack_entry = rcv_ack_hashtbl_lookup(tcp_key64);
    rcu_read_unlock();
    // if (likely(ack_entry)) {
    //     spin_lock(&ack_entry->lock);
    //     if (before(ntohl(tcp->ack_seq), ack_entry->snd_una)) {
    //         printk(KERN_INFO "STALE ACKS FOUND");
    //     }
    //     acked = ntohl(tcp->ack_seq) - ack_entry->snd_una;
    //     ack_entry->snd_una = ntohl(tcp->ack_seq);
    //     /*theory behind: When a TCP sender receives 3 duplicate acknowledgements
    //      * for the same piece of data (i.e. 4 ACKs for the same segment,
    //      * which is not the most recently sent piece of data), then most likely,
    //      * packet was lost in the netowrk. DUP-ACK is faster than RTO*/
    //     if (acked == 0 && before(ack_entry->snd_una, ack_entry->snd_nxt) && (tcp_data_len == 0)
    //         && ack_entry->prior_real_rcv_wnd == ntohs(tcp->window)){
    //             ack_entry->dupack_cnt++;
    //     }
    //     ack_entry->prior_real_rcv_wnd = ntohs(tcp->window);

    //     //ovs_tcp_reno_cong_avoid(ack_entry, acked);

    //     printk(KERN_INFO "current RWND is:%u.\n", ack_entry->rwnd);

    //     //peer subflow modification
    //     struct rcv_ack *peer_ack_entry;
    //     peer_ack_entry = NULL;
    //     rcu_read_lock();
    //     peer_ack_entry = rcv_ack_hashtbl_lookup(ack_entry->peer_subflow_key);
    //     rcu_read_unlock();
    //     if(peer_ack_entry) {
    //         peer_ack_entry->rwnd = max(RWND_MIN, ack_entry->rwnd);
    //     }
    //     peer_ack_entry = NULL;
    //     //Execute

    //      if ((ntohs(tcp->window) << ack_entry->snd_wscale) > ack_entry->rwnd) {
    //          u16 enforce_win = ack_entry->rwnd >> ack_entry->snd_wscale;
    //          tcp->window = htons(enforce_win);
    //      }
        
    //     spin_unlock(&ack_entry->lock);
    // }//finish likely(ack_entry)
    ack_entry = NULL;
}


void virtopia_proc_fin(struct sk_buff *skb, struct iphdr *nh, struct tcphdr *tcp) {
    u32 srcip;
    u32 dstip;
    u16 srcport;
    u16 dstport;
    u64 tcp_key64;

    srcip = ntohl(nh->saddr);
    dstip = ntohl(nh->daddr);
    srcport = ntohs(tcp->source);
    dstport = ntohs(tcp->dest);

	struct rcv_ack *new_entry;
    new_entry = NULL;

    tcp_key64 = get_tcp_key64(dstip, srcip, dstport, srcport);

    rcu_read_lock();
    new_entry = rcv_ack_hashtbl_lookup(tcp_key64);
    rcu_read_unlock();
    if (likely(new_entry)) {
        rcv_ack_hashtbl_delete(new_entry);
    }

    #ifdef IPERF_DEBUG
    if (dstport == 5001) {
		printk(KERN_INFO "rcv_ack_hashtbl new entry deleted. %d --> %d\n",
            		srcport, dstport);
	}
	#endif

    new_entry = NULL;
}
