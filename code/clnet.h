/**
 * Copyright (C) 2012 Joao Paulo de Souza Medeiros.
 *
 * Author(s): Joao Paulo de Souza Medeiros <jpsm1985@gmail.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
 */

#ifndef CLNET_H
#define CLNET_H

#include <clads/code/clads.h>
#include <netinet/in.h>

#define CLNET_SLL_ADDR_LEN      8
#define CLNET_SLL_HEADER_LEN    16

#define CLNET_ETHER_ADDR_LEN    6
#define CLNET_ETHER_MAX_LEN     1518
#define CLNET_ETHER_HEADER_LEN  14


typedef struct clnet_linux_sll_header
{
    u_short packet_type;                    // packet type
    u_short arphrd;                         // linux ARPHRD_ value
    u_short length;                         // length of the sender address
    u_char address[CLNET_SLL_ADDR_LEN];     // first 8-byte sender address
    u_short ether_type;                     // IP? ARP? RARP? etc
} clnet_linux_sll_header_type;

typedef struct clnet_ethernet_header
{
    u_char d_host[CLNET_ETHER_ADDR_LEN];    // destination host address
    u_char s_host[CLNET_ETHER_ADDR_LEN];    // source host address
    u_short type;                           // IP? ARP? RARP? etc
} clnet_ethernet_header_type;

typedef struct clnet_ipv4_header
{
    u_char vhl;                     // version << 4 | header length >> 2
#define CLNET_IPV4_HEADER_LENGTH(ip)  (((ip)->vhl) & 0x0f)
#define CLNET_IPV4_VERSION(ip)        (((ip)->vhl) >> 4)
    u_char tos;                     // type of service
    u_short length;                 // total length
    u_short id;                     // identification
    u_short offset;                 // fragment offset field
#define CLNET_IPV4_RF       0x8000  // reserved fragment flag
#define CLNET_IPV4_DF       0x4000  // dont fragment flag
#define CLNET_IPV4_MF       0x2000  // more fragments flag
#define CLNET_IPV4_OFFMASK  0x1fff  // mask for fragmenting bits
    u_char ttl;                     // time to live
    u_char protocol;                // protocol
    u_short checksum;               // checksum
    struct in_addr s_addr;          // source address
    struct in_addr d_addr;          // destination address
} clnet_ipv4_header_type;

typedef struct clnet_tcp_header
{
    u_short sport;          // source port
    u_short dport;          // destination port
    u_int32_t seq;          // sequence number
    u_int32_t ack;          // acknowledgement number
    u_char offx2;           // data offset, rsvd
#define CLNET_TCP_OFF(tcp)  (((tcp)->offx2 & 0xf0) >> 4)
    u_char flags;
#define CLNET_TCP_FIN       0x01
#define CLNET_TCP_SYN       0x02
#define CLNET_TCP_RST       0x04
#define CLNET_TCP_PUSH      0x08
#define CLNET_TCP_ACK       0x10
#define CLNET_TCP_URG       0x20
#define CLNET_TCP_ECE       0x40
#define CLNET_TCP_CWR       0x80
    u_short window;         // window
    u_short checksum;       // checksum
    u_short urgent_pointer; // urgent pointer
} clnet_tcp_header_type;


/**
 *
 */
inline clads_void_type
clnet_initialize(clads_void_type);

/**
 *
 */
inline clads_void_type
clnet_finalize(clads_void_type);

#endif
