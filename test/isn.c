/**
 * Copyright (C) 2008 Joao Paulo de Souza Medeiros.
 *
 * Author(s): João Paulo de Souza Medeiros <ignotus21@gmail.com>
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

#include "../code/clnet.h"
#include <libnet.h>
#include <pcap.h>
#include <stdio.h>
#include <sys/shm.h>

#define USAGE   "\nUsage: %s -s -t [-f -p] [-a] [-d] [-i]\n"\
                "\t-d device (default eth0)\n"\
                "\t-s source (ip:port - 192.168.21.2:20)\n"\
                "\t-t target (ip:port - 192.168.21.1:21)\n"\
                "\t-a number of packets set to send (default 100000)\n"\
                "\t-i packet sending interval (microseconds, default 10000)\n"


/*
 * Pcap filter format and size
 * +10 - two maximum port string size
 * +32 - two maximum address string size
 *  -8 - subtract format type strings
 *  +1 - add '\0' to string
 */
#define FILTER_FORMAT   "(tcp[13] & 0x02 = 2) and "\
                        "(src port %d) and (dst port %d) and "\
                        "(src host %s) and (dst host %s)"
#define FILTER_SIZE     (strlen(FILTER_FORMAT) + 10 + 32 - 8 + 1)

unsigned int *count, datalink;

void usage(char* name)
{
    fprintf(stderr, USAGE, name);
}

void send_packets(libnet_t *lnet_handle,
                  u_int32_t src,
                  u_int32_t dst,
                  u_short src_port,
                  u_short dst_port,
                  unsigned int amount,
                  useconds_t interval)
{
    libnet_ptag_t tcp = LIBNET_PTAG_INITIALIZER,
                  ip = LIBNET_PTAG_INITIALIZER;

    while (*count < amount)
    {
        tcp = libnet_build_tcp(
                    src_port,
                    dst_port,
                    0,
                    0,
                    TH_SYN,
                    1024,
                    0,
                    0,
                    LIBNET_TCP_H,
                    NULL,
                    0,
                    lnet_handle,
                    tcp);

        ip = libnet_build_ipv4(
                LIBNET_TCP_H + LIBNET_IPV4_H,   /* length */
                0,                              /* TOS */
                0,                              /* IP ID */
                0,                              /* IP Frag */
                64,                             /* TTL */
                IPPROTO_TCP,                    /* protocol */
                0,                              /* checksum */
                src,                            /* source IP */
                dst,                            /* destination IP */
                NULL,                           /* payload */
                0,                              /* payload size */
                lnet_handle,                    /* libnet context */
                ip);                            /* ptag */

        if (ip == -1)
        {
            fprintf(stderr,
                    "Can't build IP: %s.\n",
                    libnet_geterror(lnet_handle));

            exit(EXIT_FAILURE);
        }

        int res = libnet_write(lnet_handle);

        if (res == -1)
        {
            fprintf(stderr,
                    "libnet_write: %s.\n",
                    libnet_geterror(lnet_handle));

            exit(EXIT_FAILURE);
        }

        if (interval > 0)
            usleep(interval);
    }
}

void
get_tcp_isn(u_char *args,
            const struct pcap_pkthdr *header,
            const u_char *packet)
{
    clnet_ipv4_header_type *ip;
    clnet_tcp_header_type *tcp;
    clads_size_type s_link, s_ip;

    u_int32_t seq;

    switch (datalink)
    {
        case DLT_EN10MB:
            s_link = CLNET_ETHER_HEADER_LEN;
            break;
        case DLT_LINUX_SLL:
            s_link = CLNET_SLL_HEADER_LEN;
            break;
        default:
            fprintf(stderr, "Unsuported datalink.\n");
            exit(EXIT_FAILURE);
    }

    ip = (clnet_ipv4_header_type *) (packet + s_link);
    s_ip = CLNET_IPV4_HEADER_LENGTH(ip) * 4;
    tcp = (clnet_tcp_header_type *) (packet + s_link + s_ip);
    seq = ntohl(tcp->seq);

    printf("%u\n", seq);

    *count += 1;
}

int main(int argc, char **argv)
{
    /**
     *
     */
    int shmid;
    key_t key = rand();

    libnet_t *lnet_handle = NULL;
    pcap_t *pcap_handle;

    char lnet_errbuf[LIBNET_ERRBUF_SIZE];
    char pcap_errbuf[PCAP_ERRBUF_SIZE];
    char *cp, *filter, *dst_str, *src_str, *device = "eth0";
    struct bpf_program fp;
    u_int32_t dst, src;
    u_short dst_port, src_port;
    pid_t pid;
    unsigned int c,
                 amount = 10000;    /* 10000 packets sent by default */
    useconds_t interval = 10000;    /* 10 miliseconds by default */

    if (argc < 5)
    {
        usage(argv[0]);

        exit(EXIT_FAILURE);
    }

    /**
     * Getting arguments
     */
    while ((c = getopt(argc, argv, "d:s:t:a:i:")) != EOF)
    {
        switch(c)
        {
            case 'd':
                device = malloc(sizeof(char) * strlen(optarg));
                strcpy(device, optarg);
                break;

            case 's':
                if (!(cp = strrchr(optarg, ':')))
                {
                    usage(argv[0]);

                    exit(EXIT_FAILURE);
                }

                *cp++ = 0;
                src_port = (u_short)atoi(cp);

                src = libnet_name2addr4(lnet_handle, optarg, LIBNET_RESOLVE);
                src_str = malloc(sizeof(char) * (strlen(optarg) + 1));
                strcpy(src_str, optarg);

                if (src == -1)
                {
                    fprintf(stderr,
                            "Bad source (%s).\n",
                            libnet_geterror(lnet_handle));

                    exit(EXIT_FAILURE);
                }

                break;

            case 't':
                if (!(cp = strrchr(optarg, ':')))
                {
                    usage(argv[0]);

                    exit(EXIT_FAILURE);
                }

                *cp++ = 0;
                dst_port = (u_short)atoi(cp);

                dst = libnet_name2addr4(lnet_handle, optarg, LIBNET_RESOLVE);
                dst_str = malloc(sizeof(char) * (strlen(optarg) + 1));
                strcpy(dst_str, optarg);

                if (dst == -1)
                {
                    fprintf(stderr,
                            "Bad target (%s).\n",
                            libnet_geterror(lnet_handle));

                    exit(EXIT_FAILURE);
                }

                break;

            case 'i':
                interval = atoi(optarg);
                break;

            case 'a':
                amount = atoi(optarg);
                break;
        }
    }


    /**
     * Initialize libnet
     */
    lnet_handle = libnet_init(LIBNET_RAW4, device, lnet_errbuf);

    if (lnet_handle == NULL)
    {
        fprintf(stderr, "libnet_init() failed: %s.\n", lnet_errbuf);

        exit(EXIT_FAILURE);
    }

    /**
     * Initialize libpcap
     */
    pcap_handle = pcap_open_live(device,
                                 CLNET_ETHER_MAX_LEN,
                                 1,
                                 1000,
                                 pcap_errbuf);

    if (pcap_handle == NULL)
    {
        fprintf(stderr, "Couldn't open device %s: %s.\n", device, pcap_errbuf);

        exit(EXIT_FAILURE);
    }

    datalink = pcap_datalink(pcap_handle);

    if (datalink != DLT_EN10MB && datalink != DLT_LINUX_SLL)
    {
        fprintf(stderr, "%s (%d) is not an Ethernet.\n", device, datalink);

        exit(EXIT_FAILURE);
    }

    filter = (char*) malloc(FILTER_SIZE);

    sprintf(filter,
            FILTER_FORMAT,
            dst_port,
            src_port,
            dst_str,
            src_str);

    if (pcap_compile(pcap_handle, &fp, filter, 0, 0) == -1)
    {
        fprintf(stderr,
                "Couldn't parse filter '%s': %s.\n",
                filter,
                pcap_geterr(pcap_handle));

        exit(EXIT_FAILURE);
    }

    if (pcap_setfilter(pcap_handle, &fp) == -1)
    {
        fprintf(stderr,
                "Couldn't install filter %s: %s.\n",
                filter, pcap_geterr(pcap_handle));

        exit(EXIT_FAILURE);
    }

    /**
     *
     */
    if ((shmid = shmget(key, sizeof(unsigned int), IPC_CREAT | 0666)) < 0)
    {
        perror("shmget");

        exit(1);
    }

    if ((count = shmat(shmid, NULL, 0)) == (unsigned int *) -1)
    {
        perror("shmat");

        exit(1);
    }

    *count = 0;

    pid = fork();

    if (pid == 0)
    {
        pcap_loop(pcap_handle, amount, get_tcp_isn, NULL);

        fflush(stdout);

        pcap_freecode(&fp);
        pcap_close(pcap_handle);
    }
    else
    {
        send_packets(lnet_handle,
                     src,
                     dst,
                     src_port,
                     dst_port,
                     amount,
                     interval);

        libnet_destroy(lnet_handle);
    }

    exit(EXIT_SUCCESS);
}
