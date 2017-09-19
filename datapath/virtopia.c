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

    struct rcv_ack *new_entry = NULL;
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

    u64 sender_key; 
    u64 receiver_key;
    u32 token;

    sender_key = mopt.mptcp_sender_key;
    receiver_key = mopt.mptcp_receiver_key;
    token = mopt.mptcp_rem_token;

	printk(KERN_INFO "[MPTCP SYN] sender_key is %llu, receiver_key is %llu, token is %u", 
	        	sender_key, receiver_key, token);

    //MPTCP_SYN_INIT
    if (sender_key != 0 && receiver_key == 0 && token == 0) {
    	#ifdef IPERF_DEBUG
		if (dstport == 5001) { //iperf test
    		printk(KERN_INFO "[MPTCP SYN] MPTCP_SYN_INIT");
    	}
    	#endif
    }

    //MPTCP_SYN_JOIN
    if (token != 0) {
    	#ifdef IPERF_DEBUG
		if (dstport == 5001) { //iperf test
    		printk(KERN_INFO "[MPTCP SYN] MPTCP_SYN_JOIN");
    	}
    	#endif

        rcu_read_lock();  
        struct token_key *existing_token_key = NULL;
        existing_token_key = token_key_hashtbl_lookup(token);
        rcu_read_unlock();

        if(existing_token_key != NULL) {
            struct rcv_ack *master_subflow_ack_entry = NULL;
            master_subflow_ack_entry = rcv_ack_hashtbl_lookup(existing_token_key->tcp_key64);
            //mutual key association
            if (master_subflow_ack_entry != NULL) {
                master_subflow_ack_entry->peer_subflow_key = tcp_key64;
                new_entry->peer_subflow_key = master_subflow_ack_entry->key;
            }
            master_subflow_ack_entry = NULL;
        }
    }

    new_entry = NULL;
}


void virtopia_proc_ack(struct sk_buff *skb, struct iphdr *nh, struct tcphdr *tcp) {
	u32 srcip;
    u32 dstip;
    u16 srcport;
    u16 dstport;
    u64 tcp_key64;

    srcip = ntohl(nh->saddr);
    dstip = ntohl(nh->daddr);
    srcport = ntohs(tcp->source);
    dstport = ntohs(tcp->dest);


	u32 calc_token;
    calc_token = 0;
    struct mptcp_options_received mopt;
    mptcp_init_mp_opt(&mopt);
    tcp_parse_mptcp_options(skb, &mopt);
    mptcp_key_sha1(mopt.mptcp_receiver_key, &calc_token, NULL);


    #ifdef IPERF_DEBUG
    if (dstport == 5001) {
    	printk(KERN_INFO "[MPTCP ACK] receiver_key is %llu, calculated token is %u", 
    		mopt.mptcp_receiver_key, calc_token);
    }
    #endif

	struct rcv_ack *cur_entry = NULL;
    tcp_key64 = get_tcp_key64(dstip, srcip, dstport, srcport);
    rcu_read_lock();
    cur_entry = rcv_ack_hashtbl_lookup(tcp_key64);
    rcu_read_unlock();

	cur_entry->remote_token = calc_token;
	cur_entry = NULL;


	struct token_key *new_token_key = NULL;
    rcu_read_lock();
    new_token_key = token_key_hashtbl_lookup(calc_token);
    rcu_read_unlock();
    if (likely(!new_token_key)) {
        new_token_key = kzalloc(sizeof(*new_token_key), GFP_KERNEL);
        new_token_key->token = calc_token;
        new_token_key->tcp_key64 = get_tcp_key64(dstip, srcip, dstport, srcport);
        new_token_key->srcip = srcip;
        new_token_key->dstip = dstip;
        new_token_key->srcport = srcport;
        new_token_key->dstport = dstport;
        rcv_ack_hashtbl_insert(calc_token, new_token_key);
    }
    new_token_key = NULL;
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

	struct rcv_ack *new_entry = NULL;

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