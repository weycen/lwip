/**
 * lwip_arp_filter_netif_fn.c
 *
 * Version:     V1.0.0
 * Created on:  2021-09-28
 * Author:      Qiu Chengwei
 * Description:
 *
 *
 * Copyright (c) 2021 Nanjing Zitai Xinghe Electronics Co., Ltd.
 * All rights reserved.
 *
 * 1 tab == 2 spaces!
 */

/** 头文件包含顺序(以空行分隔): 关联.h, C库, C++库(无扩展), 其它库, 本项目.h
 * Includes ------------------------------------------------------------------*/
#include "lwip_arp_filter_netif_fn.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "netif/ethernet.h"

/* Types, Constants, Macros, Variables ---------------------------------------*/

/* Prototypes of private function --------------------------------------------*/

/* Definition of functions ---------------------------------------------------*/

/**
 *
 *
 * @param p the received packet, p->payload pointing to the ethernet header
 * @param netif the network interface on which the packet was received
 *
 * @see LWIP_ARP_FILTER_NETIF
 */
struct netif * lwip_arp_filter_netif_fn(struct pbuf *p, struct netif *netif, u16_t type) {

  struct netif *netif;
  struct etharp_hdr *etharphdr;

  switch (type) {
    /* IP packet? */
    case PP_HTONS(ETHTYPE_IP):
      break;

    /* ARP packet */
    case PP_HTONS(ETHTYPE_ARP):
    etharphdr = (struct etharphdr *)((struct eth_hdr*)p->payload + 1);

    /* iterate through netifs */
    NETIF_FOREACH(netif) {
    if ((ip4_addr_cmp(etharphdr->dipaddr, netif_ip4_gw(netif_ip4_addr))) {
        /* return netif on which to forward IP packet */
        return netif;
      }
    }
    break;

    default:
    netif = netif_list;
    break;
  }
}

static void
create_arp_response(ip4_addr_t *adr)
{
  int k;
  struct eth_hdr *ethhdr;
  struct etharp_hdr *etharphdr;
  struct pbuf *p = pbuf_alloc(PBUF_RAW, sizeof(struct eth_hdr) + sizeof(struct etharp_hdr), PBUF_RAM);
  if(p == NULL) {
    FAIL_RET();
  }
  ethhdr = (struct eth_hdr*)p->payload;
  etharphdr = (struct etharp_hdr*)(ethhdr + 1);

  ethhdr->dest = test_ethaddr;
  ethhdr->src = test_ethaddr2;
  ethhdr->type = htons(ETHTYPE_ARP);

  etharphdr->hwtype = htons(LWIP_IANA_HWTYPE_ETHERNET);
  etharphdr->proto = htons(ETHTYPE_IP);
  etharphdr->hwlen = ETHARP_HWADDR_LEN;
  etharphdr->protolen = sizeof(ip4_addr_t);
  etharphdr->opcode = htons(ARP_REPLY);

  SMEMCPY(&etharphdr->sipaddr, adr, sizeof(ip4_addr_t));
  SMEMCPY(&etharphdr->dipaddr, &test_ipaddr, sizeof(ip4_addr_t));

  k = 6;
  while(k > 0) {
    k--;
    /* Write the ARP MAC-Addresses */
    etharphdr->shwaddr.addr[k] = test_ethaddr2.addr[k];
    etharphdr->dhwaddr.addr[k] = test_ethaddr.addr[k];
    /* Write the Ethernet MAC-Addresses */
    ethhdr->dest.addr[k] = test_ethaddr.addr[k];
    ethhdr->src.addr[k]  = test_ethaddr2.addr[k];
  }

  ethernet_input(p, &test_netif);
}