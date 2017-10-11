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

static unsigned int dctcp_shift_g __read_mostly = 4; /* g = 1/2^4 */
module_param(dctcp_shift_g, uint, 0644);
MODULE_PARM_DESC(dctcp_shift_g, "parameter g for updating dctcp_alpha");

#define RWND_INIT 10U*MSS
#define RWND_CLAMP (10*1000*1000*4/8) //4 means the maximal latency expected (4 msec), in bytes
#define RWND_MIN MSS
#define RWND_STEP MSS
#define RWND_SSTHRESH_INIT (RWND_CLAMP >> 1)

#define DCTCP_ALPHA_INIT 1024U
#define DCTCP_MAX_ALPHA  1024U

#define OUT 0
#define IN 1

#define IPERF_DEBUG 1


enum {
    OVS_PKT_IN = 1U, //packets come to the host
    OVS_PKT_OUT = 3U, //packets go to the network (switch), see "ip_summed_*"
};

enum {
    OVS_ECN_MASK = 3U,
    OVS_ECN_ZERO = 0U,
    OVS_ECN_ONE = 1U,
    OVS_ECN_FAKE = 4U, //set the second highest bit of 3 reserved bits in TCP header
    OVS_ECN_FAKE_CLEAR = 11U, // 1011 (binary) = 11 (decimal)
    OVS_ACK_SPEC_SET = 8U, //set the highest bit of 3 reserved bits in TCP header
    OVS_ACK_PACK_SET = 2U, //set the third highest bit of 3 reserved bits in TCP header
    OVS_ACK_PACK_CLEAR = 13U, // 1101 (binary) = 13 (decimal)
};

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


void virtopia_init_rcv_ack(struct rcv_ack *new_entry, struct tcphdr *tcp, int direction, struct sk_buff *skb) 
{
    if (direction == OUT) {
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
    } else if (direction == IN) {
        new_entry->snd_wscale = ovs_tcp_parse_options(skb);
    }
}

void virtopia_init_rcv_data(struct rcv_data *new_entry, struct tcphdr *tcp) 
{
    new_entry->ecn_bytes_per_ack = 0;
    new_entry->total_bytes_per_ack = 0;
}

/*
 * Process SYN packet
 * TCP_SYN / MPTCP_SYN_INI / MPTCP_SYN_JOIN
 */
void virtopia_out_syn(struct sk_buff *skb, struct iphdr *nh, struct tcphdr *tcp) 
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

    virtopia_init_rcv_ack(new_entry, tcp, OUT, skb);
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



void virtopia_in_syn(struct sk_buff *skb, struct iphdr *nh, struct tcphdr *tcp) 
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

    struct rcv_ack *ack_entry;
    ack_entry = NULL;

    struct rcv_data *data_entry;
    data_entry = NULL;


    tcp_key64 = get_tcp_key64(dstip, srcip, dstport, srcport); 

    rcu_read_lock();
    ack_entry = rcv_ack_hashtbl_lookup(tcp_key64);
    rcu_read_unlock();

    rcu_read_lock();
    data_entry = rcv_data_hashtbl_lookup(tcp_key64);
    rcu_read_unlock();

    if (likely(!ack_entry)) {
        ack_entry = kzalloc(sizeof(*ack_entry), GFP_KERNEL);
        ack_entry->key = tcp_key64;
        rcv_ack_hashtbl_insert(tcp_key64, ack_entry);
    }

    virtopia_init_rcv_ack(ack_entry, tcp, IN, skb);
    spin_lock_init(&ack_entry->lock);


    if (likely(!data_entry)) {
        data_entry = kzalloc(sizeof(*data_entry), GFP_KERNEL);
        data_entry->key = tcp_key64;
        rcv_data_hashtbl_insert(tcp_key64, data_entry);
    }

    virtopia_init_rcv_data(data_entry, tcp);
    spin_lock_init(&data_entry->lock);

}



void virtopia_out_ack(struct sk_buff *skb, struct iphdr *nh, struct tcphdr *tcp) 
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

    if (mopt.saw_mpc == 1 && mopt.is_mp_join == 0 && mopt.join_ack == 1) { //this is a join ack
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

        if (likely(cur_entry)) {
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

    if (mopt.saw_mpc == 0 && mopt.is_mp_join == 0 && mopt.join_ack == 0) {
         #ifdef IPERF_DEBUG
         if (dstport == 5001) {
             printk(KERN_INFO "[MPTCP ACK] srcport is %d, dstport is %d, saw_mpc is %d, is_mp_join is %d, join_ack is %d", 
             srcport, dstport, mopt.saw_mpc, mopt.is_mp_join, mopt.join_ack);
         }
         #endif

         virtopia_out_data_ack(skb, nh, tcp);

    }

}



void virtopia_out_data_ack(struct sk_buff *skb, struct iphdr *nh, struct tcphdr *tcp) 
{
    // Pack ECN Info and clear ECN info
    u32 srcip;
    u32 dstip;
    u16 srcport;
    u16 dstport;
    u64 tcp_key64;

    srcip = ntohl(nh->saddr);
    dstip = ntohl(nh->daddr);
    srcport = ntohs(tcp->source);
    dstport = ntohs(tcp->dest);

    struct rcv_data *data_entry;
    data_entry = NULL;
    tcp_key64 = get_tcp_key64(dstip, srcip, dstport, srcport); //direction
    rcu_read_lock();
    data_entry = rcv_data_hashtbl_lookup(tcp_key64);
    rcu_read_unlock();
    if (likely(data_entry)) {
        vcc_pack_ecn_info(skb, data_entry->ecn_bytes_per_ack, data_entry->total_bytes_per_ack);
        spin_lock(&data_entry->lock);
        data_entry->total_bytes_per_ack = 0 ;
        data_entry->ecn_bytes_per_ack = 0;
        spin_unlock(&data_entry->lock);
    }
    data_entry = NULL;
}



void virtopia_in_data_ack(struct sk_buff *skb, struct iphdr *nh, struct tcphdr *tcp) 
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

    int tcp_data_len;
    tcp_data_len = ntohs(nh->tot_len) - (nh->ihl << 2) - (tcp->doff << 2);

    struct rcv_ack *ack_entry;
    ack_entry = NULL;
    tcp_key64 = get_tcp_key64(srcip, dstip, srcport, dstport);

    u32 acked = 0;
    rcu_read_lock();
    ack_entry = rcv_ack_hashtbl_lookup(tcp_key64);
    if (likely(ack_entry)) {
        spin_lock(&ack_entry->lock);
        if (before(ntohl(tcp->ack_seq), ack_entry->snd_una)) {
            printk(KERN_INFO "STALE ACKS FOUND");
        }
        acked = ntohl(tcp->ack_seq) - ack_entry->snd_una;
        ack_entry->snd_una = ntohl(tcp->ack_seq);
        /*theory behind: When a TCP sender receives 3 duplicate acknowledgements
         * for the same piece of data (i.e. 4 ACKs for the same segment,
         * which is not the most recently sent piece of data), then most likely,
         * packet was lost in the netowrk. DUP-ACK is faster than RTO*/
        if (acked == 0 && before(ack_entry->snd_una, ack_entry->snd_nxt) && (tcp_data_len == 0)
            && ack_entry->prior_real_rcv_wnd == ntohs(tcp->window)){
                ack_entry->dupack_cnt++;
        }
        ack_entry->prior_real_rcv_wnd = ntohs(tcp->window);


        vcc_unpack_ecn_info(skb, ack_entry->ecn_bytes, ack_entry->total_bytes);
        vcc_dctcp_update_alpha(ack_entry);

        unsigned long reduced_win;
        reduced_win = ((unsigned long)vcc_dctcp_ssthresh(ack_entry));

        ack_entry->rwnd = max(RWND_MIN, (unsigned int)reduced_win);
        printk(KERN_INFO "current RWND is:%u.\n", ack_entry->rwnd);
        spin_unlock(&ack_entry->lock);

        //peer subflow modification
        struct rcv_ack *peer_ack_entry;
        peer_ack_entry = NULL;
        rcu_read_lock();
        peer_ack_entry = rcv_ack_hashtbl_lookup(ack_entry->peer_subflow_key);
        rcu_read_unlock();
        if(peer_ack_entry) {
            peer_ack_entry->rwnd = max(RWND_MIN, (unsigned int)reduced_win);
        }
        peer_ack_entry = NULL;
        //Execute
        if ((ntohs(tcp->window) << ack_entry->snd_wscale) > ack_entry -> rwnd) {
            u16 enforce_win = ack_entry->rwnd >> ack_entry->snd_wscale;
            tcp->window = htons(enforce_win);
        }
    }//finish likely(ack_entry)
    ack_entry = NULL;
    rcu_read_unlock();   
}



void virtopia_in_ack(struct sk_buff *skb, struct iphdr *nh, struct tcphdr *tcp) {

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

    if (mopt.saw_mpc == 0 && mopt.is_mp_join == 0 && mopt.join_ack == 0) {
         #ifdef IPERF_DEBUG
         if (dstport == 5001) {
             printk(KERN_INFO "[MPTCP ACK] srcport is %d, dstport is %d, saw_mpc is %d, is_mp_join is %d, join_ack is %d", 
             srcport, dstport, mopt.saw_mpc, mopt.is_mp_join, mopt.join_ack);
         }
         #endif
         virtopia_in_data_ack(skb, nh, tcp);
    }
}



void virtopia_out_data(struct sk_buff *skb, struct iphdr *nh, struct tcphdr *tcp) 
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

    struct rcv_ack *ack_entry;
    ack_entry = NULL;
    tcp_key64 = get_tcp_key64(dstip, srcip, dstport, srcport);


    int tcp_data_len;
    u32 end_seq;

    //first task, update "snd_nxt" in "rcv_ack"
    tcp_data_len = ntohs(nh->tot_len) - (nh->ihl << 2) - (tcp->doff << 2);
    end_seq = ntohl(tcp->seq) + tcp_data_len;

    rcu_read_lock();
    ack_entry = rcv_ack_hashtbl_lookup(tcp_key64);
    if (likely(ack_entry)) {
        spin_lock(&ack_entry->lock);
        if (tcp_data_len > 0 && after(end_seq, ack_entry->snd_nxt)) {
            ack_entry->snd_nxt = end_seq;
            /*printk(KERN_INFO "tcp_data_len:%d, snd_nxt updated: %u (%d --> %d)\n",
                tcp_data_len, end_seq, srcport, dstport);
            */
        }
        spin_unlock(&ack_entry->lock);
    }
    rcu_read_unlock();
}


void virtopia_in_data(struct sk_buff *skb, struct iphdr *nh, struct tcphdr *tcp) 
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

    struct rcv_data *data_entry;
    data_entry = NULL;
    tcp_key64 = get_tcp_key64(dstip, srcip, dstport, srcport);


    int tcp_data_len;
    if (tcp_data_len > 0) {
        rcu_read_lock();
        data_entry = rcv_data_hashtbl_lookup(tcp_key64);
        if (likely(data_entry)) {
            spin_lock(&data_entry->lock);
            data_entry->total_bytes_per_ack += tcp_data_len;
            if ((nh->tos & OVS_ECN_MASK) == OVS_ECN_MASK) {
                data_entry->ecn_bytes_per_ack += tcp_data_len;
            }
            spin_unlock(&data_entry->lock);
        }
        rcu_read_unlock();
    }
}


void virtopia_out_fin(struct sk_buff *skb, struct iphdr *nh, struct tcphdr *tcp) {
    u32 srcip;
    u32 dstip;
    u16 srcport;
    u16 dstport;
    u64 tcp_key64;

    srcip = ntohl(nh->saddr);
    dstip = ntohl(nh->daddr);
    srcport = ntohs(tcp->source);
    dstport = ntohs(tcp->dest);

	struct rcv_ack *existing_entry;
    existing_entry = NULL;

    tcp_key64 = get_tcp_key64(dstip, srcip, dstport, srcport);

    rcu_read_lock();
    existing_entry = rcv_ack_hashtbl_lookup(tcp_key64);
    rcu_read_unlock();
    

    if (likely(existing_entry)) {
        struct token_key *existing_token_key;
        existing_token_key = NULL;
        existing_token_key = token_key_hashtbl_lookup(existing_entry->remote_token);
        if (likely(existing_token_key)) {
            token_key_hashtbl_delete(existing_token_key);
            #ifdef IPERF_DEBUG
            if (dstport == 5001) {
                printk(KERN_INFO "token_key_hashtble entry deleted. %d --> %d\n",
                            srcport, dstport);
            }
            #endif
        }
        existing_token_key = NULL;
        rcv_ack_hashtbl_delete(existing_entry);
        #ifdef IPERF_DEBUG
        if (dstport == 5001) {
            printk(KERN_INFO "rcv_ack_hashtbl entry deleted. %d --> %d\n",
                        srcport, dstport);
        }
        #endif
    }
    existing_entry = NULL;
}



void virtopia_in_fin(struct sk_buff *skb, struct iphdr *nh, struct tcphdr *tcp) {
    u32 srcip;
    u32 dstip;
    u16 srcport;
    u16 dstport;
    u64 tcp_key64;

    srcip = ntohl(nh->saddr);
    dstip = ntohl(nh->daddr);
    srcport = ntohs(tcp->source);
    dstport = ntohs(tcp->dest);

    struct rcv_ack *existing_ack;
    existing_ack = NULL;

    tcp_key64 = get_tcp_key64(dstip, srcip, dstport, srcport);

    rcu_read_lock();
    existing_ack = rcv_ack_hashtbl_lookup(tcp_key64);
    rcu_read_unlock();
    

    if (likely(existing_ack)) {
        struct token_key *existing_token_key;
        existing_token_key = NULL;
        existing_token_key = token_key_hashtbl_lookup(existing_ack->remote_token);
        if (likely(existing_token_key)) {
            token_key_hashtbl_delete(existing_token_key);
            #ifdef IPERF_DEBUG
            if (dstport == 5001) {
                printk(KERN_INFO "token_key_hashtble entry deleted. %d --> %d\n",
                            srcport, dstport);
            }
            #endif
        }
        existing_token_key = NULL;
        rcv_ack_hashtbl_delete(existing_ack);
        #ifdef IPERF_DEBUG
        if (dstport == 5001) {
            printk(KERN_INFO "rcv_ack_hashtbl entry deleted. %d --> %d\n",
                        srcport, dstport);
        }
        #endif
    }
    existing_ack = NULL;

    struct rcv_data *existing_data;
    existing_data = NULL;
    rcu_read_lock();
    existing_data = rcv_data_hashtbl_lookup(tcp_key64);
    rcu_read_unlock();

    if (likely(existing_data)) {
        rcv_data_hashtbl_delete(existing_data);
        #ifdef IPERF_DEBUG
        if (dstport == 5001) {
            printk(KERN_INFO "rcv_data_hashtbl entry deleted. %d --> %d\n",
                        srcport, dstport);
        }
        #endif
    }
    existing_data = NULL;
}





void vcc_tcp_slow_start(struct rcv_ack *rack, u32 acked) {
//”acked” means the number of bytes acked by an ACK
    u32 rwnd = rack->rwnd + acked;

    if (rwnd > rack->rwnd_ssthresh)
        rwnd = rack->rwnd_ssthresh + RWND_STEP;

    rack->rwnd = min(rwnd, rack->rwnd_clamp);
}

/* In theory this is tp->snd_cwnd += 1 / tp->snd_cwnd (or alternative w) */
/* In theory this is tp->rwnd += MSS / tp->rwnd (or alternative w) */
void vcc_tcp_cong_avoid_ai(struct rcv_ack *rack, u32 w, u32 acked) {
    if (rack->snd_rwnd_cnt >= w) {
        if (rack->rwnd < rack->rwnd_clamp)
            rack->rwnd += RWND_STEP;
        rack->snd_rwnd_cnt = 0;
    } else {
        rack->snd_rwnd_cnt += acked;
    }

    rack->rwnd = min(rack->rwnd, rack->rwnd_clamp);
}

/*
* TCP Reno congestion control
* This is special case used for fallback as well.
*/
/* This is Jacobson's slow start and congestion avoidance.
* SIGCOMM '88, p. 328.
*/
void vcc_tcp_reno_cong_avoid(struct rcv_ack *rack, u32 acked) {
    /* In "safe" area, increase. */
    if (rack->rwnd <= rack->rwnd_ssthresh)
        vcc_tcp_slow_start(rack, acked);
    /* In dangerous area, increase slowly. */
    else
        vcc_tcp_cong_avoid_ai(rack, rack->rwnd, acked);
}

/* Slow start threshold is half the congestion window (min 2) */
u32 vcc_tcp_reno_ssthresh(struct rcv_ack *rack) {
    return max(rack->rwnd >> 1U, 2U);
}

void vcc_dctcp_reset(struct rcv_ack *rack) {
    rack->next_seq = rack->snd_nxt;

    rack->ecn_bytes = 0;
    rack->total_bytes = 0;

    rack->reduced_this_win = false;
    rack->loss_detected_this_win = false;
}

u32 vcc_dctcp_ssthresh(struct rcv_ack *rack) {
    //cwnd = cwnd* (1 - alpha/2)
    //rwnd = rwnd* (1 - alpha/2)
    return max(rack->rwnd - ((rack->rwnd * rack->alpha) >> 11U), RWND_MIN);

}

void vcc_dctcp_update_alpha(struct rcv_ack *rack) {
    /* Expired RTT */
    /* update alpha once per window of data, roughly once per RTT
     * rack->total_bytes should be larger than 0
     */
    if (!before(rack->snd_una, rack->next_seq)) {

        /*printk(KERN_INFO "ecn_bytes:%u, total_bytes:%u, alpha:%u, snd_una:%u, next_seq:%u, snd_nxt:%u \n",
                *         rack->ecn_bytes, rack->total_bytes, rack->alpha, rack->snd_una, rack->next_seq, rack->snd_nxt);
        */
        /* keep alpha the same if total_bytes is zero */
        if (rack->total_bytes > 0) {

            if (rack->ecn_bytes > rack->total_bytes)
                rack->ecn_bytes = rack->total_bytes;

            /* alpha = (1 - g) * alpha + g * F */
            rack->alpha = rack->alpha -
                          (rack->alpha >> dctcp_shift_g) +
                          (rack->ecn_bytes << (10U - dctcp_shift_g)) /
                          rack->total_bytes;
            if (rack->alpha > DCTCP_MAX_ALPHA)
                rack->alpha = DCTCP_MAX_ALPHA;
        }

        vcc_dctcp_reset(rack);
        /*printk(KERN_INFO "ecn_bytes:%u, total_bytes:%u, alpha:%u\n",
                        rack->ecn_bytes, rack->total_bytes, rack->alpha);
        */

    }
}

bool vcc_may_raise_rwnd(struct rcv_ack *rack) {
    /*return ture if there is no ECN feedback received in this window yet &&
    * no packet loss is detected in this window yet
    */
    if (rack->ecn_bytes > 0 || rack->loss_detected_this_win == true)
        return false;
    else
        return true;
}

bool vcc_may_reduce_rwnd(struct rcv_ack *rack) {
    if (rack->reduced_this_win == false)
        return true;
    else
        return false;
}

int vcc_pack_ecn_info(struct sk_buff *skb, u32 ecn_bytes, u32 total_bytes) {
    struct iphdr *nh;
    struct tcphdr *tcp;

    u16 header_len;
    u16 old_total_len;
    u16 old_tcp_len;

    u8 ECN_INFO_LEN = 8;
    /*the caller makes sure this is a TCP packet*/
    nh = ip_hdr(skb);
    tcp = tcp_hdr(skb);

    header_len = skb->mac_len + (nh->ihl << 2) + 20;
    old_total_len = ntohs(nh->tot_len);
    old_tcp_len = tcp->doff << 2;

    if (skb_cow_head(skb, ECN_INFO_LEN) < 0)
        return -ENOMEM;

    skb_push(skb, ECN_INFO_LEN);
    memmove(skb_mac_header(skb) - ECN_INFO_LEN, skb_mac_header(skb), header_len);
    skb_reset_mac_header(skb);
    skb_set_network_header(skb, skb->mac_len);
    skb_set_transport_header(skb, skb->mac_len + (ip_hdr(skb)->ihl << 2));

    ecn_bytes = htonl(ecn_bytes);
    total_bytes = htonl(total_bytes);
    memcpy(skb_mac_header(skb) + header_len, &ecn_bytes, (ECN_INFO_LEN >> 1));
    memcpy(skb_mac_header(skb) + header_len + (ECN_INFO_LEN >> 1), &total_bytes, (ECN_INFO_LEN >> 1));
    /*we believe that the NIC will re-calculate checksums for us*/
    nh = ip_hdr(skb);
    tcp = tcp_hdr(skb);

    nh->tot_len = htons(old_total_len + ECN_INFO_LEN);
    tcp->doff = ((old_tcp_len + ECN_INFO_LEN) >> 2);
    /*printk("before maring pack, tcp->src:%u, tcp->dst:%u, tcp->res1:%u\n",
    * ntohs(tcp->source), ntohs(tcp->dest), tcp->res1);
    */
    tcp->res1 |= OVS_ACK_PACK_SET;
    /*printk("before maring pack, tcp->src:%u, tcp->dst:%u, tcp->res1:%u\n",
    * ntohs(tcp->source), ntohs(tcp->dest), tcp->res1);
    */
    return 0;
}

/*note, after this unpack function, tcp and ip points should be refreshed*/
int vcc_unpack_ecn_info(struct sk_buff *skb, u32 *this_ecn, u32 *this_total) {
    struct iphdr *nh;
    struct tcphdr *tcp;

    u16 header_len;
    u16 old_total_len;
    u16 old_tcp_len;
    int err;

    u8 ECN_INFO_LEN = 8;
    /*the caller makes sure this is a TCP packet*/
    nh = ip_hdr(skb);
    tcp = tcp_hdr(skb);

    header_len = skb->mac_len + (nh->ihl << 2) + 20;
    old_total_len = ntohs(nh->tot_len);
    old_tcp_len = tcp->doff << 2;

    err = skb_ensure_writable(skb, header_len);
    if (unlikely(err))
        return err;

    memset(this_ecn, 0, sizeof(*this_ecn));
    memset(this_total, 0, sizeof(*this_total));

    memcpy(this_ecn, skb_mac_header(skb) + header_len, (ECN_INFO_LEN >> 1));
    memcpy(this_total, skb_mac_header(skb) + header_len + (ECN_INFO_LEN >> 1), (ECN_INFO_LEN >> 1));

    *this_ecn = ntohl(*this_ecn);
    *this_total = ntohl(*this_total);

    //printk("we are unpack (check ip_summed):%u, ip_fast_csum:%u\n", skb->ip_summed, ip_fast_csum((u8 *)nh, nh->ihl));
    skb_postpull_rcsum(skb, skb_mac_header(skb) + header_len, ECN_INFO_LEN);

    memmove(skb_mac_header(skb) + ECN_INFO_LEN, skb_mac_header(skb), header_len);
    __skb_pull(skb, ECN_INFO_LEN);
    skb_reset_mac_header(skb);
    skb_set_network_header(skb, skb->mac_len);
    skb_set_transport_header(skb, skb->mac_len + (ip_hdr(skb)->ihl << 2));

    nh = ip_hdr(skb);
    tcp = tcp_hdr(skb);

    /*printk("we are unpack (before), tcp->src:%u, tcp->dst:%u, tcp->seq:%u, tcp->ack_seq:%u, tcp->res1:%u, nh->tot_len:%u, tcp->doff:%u, this_ecn:%u, this_total:%u, skb->ip_summed:%u\n",
        * ntohs(tcp->source), ntohs(tcp->dest), ntohl(tcp->seq), ntohl(tcp->ack_seq), tcp->res1, ntohs(nh->tot_len), tcp->doff, *this_ecn, *this_total, skb->ip_summed);
    */
    nh->tot_len = htons(old_total_len - ECN_INFO_LEN);
    csum_replace2(&nh->check, htons(old_total_len), nh->tot_len);

    tcp->doff = ((old_tcp_len - ECN_INFO_LEN) >> 2);
    tcp->res1 &= OVS_ACK_PACK_CLEAR;

    /*printk("we are unpack (after), tcp->src:%u, tcp->dst:%u, tcp->seq:%u, tcp->ack_seq:%u, tcp->res1:%u, nh->tot_len:%u, tcp->doff:%u, this_ecn:%u, this_total:%u, skb->ip_summed:%u, ip_fast_csum:%u\n",
        * ntohs(tcp->source), ntohs(tcp->dest), ntohl(tcp->seq), ntohl(tcp->ack_seq), tcp->res1, ntohs(nh->tot_len), tcp->doff, *this_ecn, *this_total, skb->ip_summed, ip_fast_csum((u8 *)nh, nh->ihl));
    */
    return 0;
}
