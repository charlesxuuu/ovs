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


 static void vcc_tcp_slow_start(struct rcv_ack *rack, u32 acked);

 static void vcc_tcp_cong_avoid_ai(struct rcv_ack *rack, u32 w, u32 acked);

 static void vcc_tcp_reno_cong_avoid(struct rcv_ack *rack, u32 acked);

 static u32 vcc_tcp_reno_ssthresh(struct rcv_ack *rack);

 static void vcc_dctcp_reset(struct rcv_ack *rack);

 static u32 vcc_dctcp_ssthresh(struct rcv_ack *rack);

 static void vcc_dctcp_update_alpha(struct rcv_ack *rack);

 static bool vcc_may_raise_rwnd(struct rcv_ack *rack);

 static bool vcc_may_reduce_rwnd(struct rcv_ack *rack);

 static int vcc_pack_ecn_info(struct sk_buff *skb, u32 ecn_bytes, u32 total_bytes);

 static int vcc_unpack_ecn_info(struct sk_buff *skb, u32 *this_ecn, u32 *this_total);

 
