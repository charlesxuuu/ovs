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

#include "vcc_dctcp.h"





static void vcc_tcp_slow_start(struct rcv_ack *rack, u32 acked) {
//”acked” means the number of bytes acked by an ACK
    u32 rwnd = rack->rwnd + acked;

    if (rwnd > rack->rwnd_ssthresh)
        rwnd = rack->rwnd_ssthresh + RWND_STEP;

    rack->rwnd = min(rwnd, rack->rwnd_clamp);
}

/* In theory this is tp->snd_cwnd += 1 / tp->snd_cwnd (or alternative w) */
/* In theory this is tp->rwnd += MSS / tp->rwnd (or alternative w) */
static void vcc_tcp_cong_avoid_ai(struct rcv_ack *rack, u32 w, u32 acked) {
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
static void vcc_tcp_reno_cong_avoid(struct rcv_ack *rack, u32 acked) {
    /* In "safe" area, increase. */
    if (rack->rwnd <= rack->rwnd_ssthresh)
        vcc_tcp_slow_start(rack, acked);
    /* In dangerous area, increase slowly. */
    else
        vcc_tcp_cong_avoid_ai(rack, rack->rwnd, acked);
}

/* Slow start threshold is half the congestion window (min 2) */
static u32 vcc_tcp_reno_ssthresh(struct rcv_ack *rack) {
    return max(rack->rwnd >> 1U, 2U);
}

static void vcc_dctcp_reset(struct rcv_ack *rack) {
    rack->next_seq = rack->snd_nxt;

    rack->ecn_bytes = 0;
    rack->total_bytes = 0;

    rack->reduced_this_win = false;
    rack->loss_detected_this_win = false;
}

static u32 vcc_dctcp_ssthresh(struct rcv_ack *rack) {
    //cwnd = cwnd* (1 - alpha/2)
    //rwnd = rwnd* (1 - alpha/2)
    return max(rack->rwnd - ((rack->rwnd * rack->alpha) >> 11U), RWND_MIN);

}

static void vcc_dctcp_update_alpha(struct rcv_ack *rack) {
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

static bool vcc_may_raise_rwnd(struct rcv_ack *rack) {
    /*return ture if there is no ECN feedback received in this window yet &&
    * no packet loss is detected in this window yet
    */
    if (rack->ecn_bytes > 0 || rack->loss_detected_this_win == true)
        return false;
    else
        return true;
}

static bool vcc_may_reduce_rwnd(struct rcv_ack *rack) {
    if (rack->reduced_this_win == false)
        return true;
    else
        return false;
}

static int vcc_pack_ecn_info(struct sk_buff *skb, u32 ecn_bytes, u32 total_bytes) {
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
static int vcc_unpack_ecn_info(struct sk_buff *skb, u32 *this_ecn, u32 *this_total) {
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
