#include "checksum.h"
#include "common.h"
#include "dhcpv6.h"
#include "eui64.h"
#include "lookup.h"
#include "protocol.h"
#include "router_hal.h"
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <net/if_arp.h>

uint8_t packet[2048];
uint8_t output[2048];
#ifndef MIN_MTU
#define MIN_MTU 1280
#endif
// for online experiment, don't change
#ifdef ROUTER_R1
// 0: fd00::1:1/112
// 1: fd00::3:1/112
// 2: fd00::6:1/112
// 3: fd00::7:1/112
in6_addr addrs[N_IFACE_ON_BOARD] = {
    {0xfd, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
     0x00, 0x01, 0x00, 0x01},
    {0xfd, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
     0x00, 0x03, 0x00, 0x01},
    {0xfd, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
     0x00, 0x06, 0x00, 0x01},
    {0xfd, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
     0x00, 0x07, 0x00, 0x01},
};
// 默认网关：fd00::3:2
in6_addr default_gateway = {0xfd, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                            0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x00, 0x02};
#else

// 自己调试用，你可以按需进行修改
// 0: fd00::0:1
// 1: fd00::1:1
// 2: fd00::2:1
// 3: fd00::3:1
in6_addr addrs[N_IFACE_ON_BOARD] = {
    {0xfd, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
     0x00, 0x00, 0x00, 0x01},
    {0xfd, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
     0x00, 0x01, 0x00, 0x01},
    {0xfd, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
     0x00, 0x02, 0x00, 0x01},
    {0xfd, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
     0x00, 0x03, 0x00, 0x01},
};
// 默认网关：fd00::1:2
in6_addr default_gateway = {0xfd, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                            0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x02};
#endif

static const int icmp_max_size = MIN_MTU - sizeof(ip6_hdr) - sizeof(icmp6_hdr);

static void assemble_IP6_hdr(uint8_t *pkt_front, in6_addr &src, in6_addr &dst, size_t len, uint8_t nxt, uint8_t hops = 255) {
  ip6_hdr *ip6 = (ip6_hdr *) pkt_front;
  ip6->ip6_flow = 0;
  ip6->ip6_vfc = 6 << 4;
  ip6->ip6_plen = htons(len - sizeof(ip6_hdr));
  ip6->ip6_nxt = nxt;
  ip6->ip6_hops = hops;
  ip6->ip6_src = src;
  ip6->ip6_dst = dst;
}

static bool get_new_ip(in6_addr *new_ip) {
  *new_ip = default_gateway;
  return true;
}

#ifndef DNS_CNT
#define DNS_CNT 2
#endif
in6_addr dns_addrs[DNS_CNT] = {
  {
    0x24, 0x02, 0xf0, 0x00, 0x00, 0x01, 0x08, 0x01, 
    0x00, 0x00, 0x00, 0x00, 0x00, 0x08, 0x00, 0x28,
  },
  {
    0x24, 0x02, 0xf0, 0x00, 0x00, 0x01, 0x08, 0x01, 
    0x00, 0x00, 0x00, 0x00, 0x00, 0x08, 0x00, 0x29,
  }
};

int main(int argc, char *argv[]) {
  // 初始化 HAL
  int res = HAL_Init(0, addrs);
  if (res < 0) {
    return res;
  }

  // 插入直连路由
  // R1：
  // fd00::1:0/112 if 0
  // fd00::3:0/112 if 1
  // fd00::6:0/112 if 2
  // fd00::7:0/112 if 3
  for (uint32_t i = 0; i < N_IFACE_ON_BOARD; i++) {
    in6_addr mask = len_to_mask(112);
    RoutingTableEntry entry = {
        .addr = addrs[i] & mask,
        .len = 112,
        .if_index = i,
        .nexthop = in6_addr{0} // 全 0 表示直连路由
    };
    update(true, entry);
  }
  // 插入默认路由
  // R1：
  // default via fd00::3:2 if 1
  RoutingTableEntry entry = {
      .addr = in6_addr{0}, .len = 0, .if_index = 1, .nexthop = default_gateway};
  update(true, entry);

  while (1) {
    uint64_t time = HAL_GetTicks();

    int mask = (1 << N_IFACE_ON_BOARD) - 1;
    ether_addr src_mac;
    ether_addr dst_mac;
    int if_index;
    res = HAL_ReceiveIPPacket(mask, packet, sizeof(packet), &src_mac, &dst_mac,
                              1000, &if_index);
    #pragma region ValidatePacketReceived
    if (res == HAL_ERR_EOF) {
      break;
    } else if (res < 0) {
      return res;
    } else if (res == 0) {
      // Timeout
      continue;
    } else if (res > sizeof(packet)) {
      // packet is truncated, ignore it
      continue;
    }

    // 检查 IPv6 头部长度
    ip6_hdr *ip6 = (ip6_hdr *)packet;
    if (res < sizeof(ip6_hdr)) {
      printf("Received invalid ipv6 packet (%d < %ld)\n", res, sizeof(ip6_hdr));
      continue;
    }
    uint16_t plen = ntohs(ip6->ip6_plen);
    if (res < plen + sizeof(ip6_hdr)) {
      printf("Received invalid ipv6 packet (%d < %d + %ld)\n", res, plen,
             sizeof(ip6_hdr));
      continue;
    }
    #pragma endregion
    // 检查 IPv6 头部目的地址是否为我自己
    bool dst_is_me = false;
    for (int i = 0; i < N_IFACE_ON_BOARD; i++) {
      if (memcmp(&ip6->ip6_dst, &addrs[i], sizeof(in6_addr)) == 0) {
        dst_is_me = true;
        break;
      }
    }

    // TODO（2 行） -- Done
    // 修改这个检查，当目的地址为 ICMPv6 RS 的
    // 组播目的地址（ff02::2，all-routers multicast address）或者
    // DHCPv6 Solicit 的组播目的地址（ff02::1:2）时也设置 dst_is_me 为 true。
    dst_is_me |= inet6_pton("ff02::2") == ip6->ip6_dst;
    dst_is_me |= inet6_pton("ff02::1:2") == ip6->ip6_dst;
    //fprintf(stderr, "IP packet received from %s, target = %s\n", inet6_ntoa(ip6->ip6_src), inet6_ntoa(ip6->ip6_dst));
    if (dst_is_me) {
      // 目的地址是我，按照类型进行处理

      // 检查 checksum 是否正确
      if (ip6->ip6_nxt == IPPROTO_UDP || ip6->ip6_nxt == IPPROTO_ICMPV6) {
        if (!validateAndFillChecksum(packet, res)) {
          printf("Received packet with bad checksum\n");
          continue;
        }
      }

      if (ip6->ip6_nxt == IPPROTO_UDP) {
        // TODO（1 行） -- Done
        // 检查 UDP 端口，判断是否为 DHCPv6 message // p.24
        size_t curr_offset = sizeof(ip6_hdr);
        udphdr *udp = (udphdr *)&packet[curr_offset];
        curr_offset += sizeof(udphdr);
        if (ntohs(udp->uh_sport) == 546 && ntohs(udp->uh_dport) == 547) {
          dhcpv6_hdr *dhcpv6 =
              (dhcpv6_hdr *)&packet[curr_offset];
          // TODO（1 行） -- Done
          // 检查是否为 DHCPv6 Solicit (1) 或 DHCPv6 Request (3) -- Done // p.24
          if (dhcpv6->msg_type == DHCPV6_MSG_SOLICIT || 
              dhcpv6->msg_type == DHCPV6_MSG_REQUEST) {
            // TODO（20 行）
            // 解析 DHCPv6 头部后的 Option，找到其中的 Client Identifier
            // 和 IA_NA 中的 IAID
            // https://www.rfc-editor.org/rfc/rfc8415.html#section-21.2
            // https://www.rfc-editor.org/rfc/rfc8415.html#section-21.4

            size_t src_offset = curr_offset + sizeof(dhcpv6_hdr);

            uint8_t client_duid[128] = {};
            size_t client_duid_len = 0;
            uint32_t iaid;
            #pragma region ReadPacketReceived
            size_t src_size = ntohs(ip6->ip6_plen) + sizeof(ip6_hdr);
            //fprintf(stderr, "Packet size = %lu\n", src_size);
            while(src_offset < src_size) {
              
              dhcpv6_opt_hdr *opthdr = (dhcpv6_opt_hdr *) &packet[src_offset];
              uint16_t opt = ntohs(opthdr->option_code);
              src_offset += sizeof(dhcpv6_opt_hdr);
              uint16_t opt_len = ntohs(opthdr->option_len);
              //fprintf(stderr, "Option code = %d, Option len = %d\n", opt, opt_len);
              //fprintf(stderr, "Validating options, src_offset = %lu, \n", src_offset);
              //display_options((uint8_t *) opthdr);
              /*for(int i = 0; i < opt_len; ++i) {
                if(i % 16 == 0) fprintf(stderr, "\n");
                fprintf(stderr, "%02x ", packet[src_offset + i]);
              }
              fprintf(stderr, "\n");*/
              switch (opt)
              {
              case DHCPV6_OPT_CLIENTID: {
                client_duid_len = ntohs(opthdr->option_len);
                for(int i = 0; i < client_duid_len; ++i) {
                  client_duid[i] = packet[src_offset + i];
                }
                break;
              }
              /*case DHCPV6_OPT_SERVERID: {
                dhcpv6_duid_hdr *duid = (dhcpv6_duid_hdr *) &packet[src_offset];
                uint16_t duidtype = duid->type;
                switch(duidtype) {
                  case DUID_LLT: {
                    in6_addr *src_ll = (in6_addr *) &packet[src_offset + sizeof(int)];
                    if(*src_ll != addrs[if_index]) {
                      continue; // not sending to self, discard
                    }
                    break;
                  }
                }
              }
              case DHCPV6_OPT_ELAPSED_TIME:
              case DHCPV6_OPT_SOL_MAX_RT:
              case DHCPV6_OPT_RECONF_ACCEPT:*/
              case DHCPV6_OPT_IA_NA: {
                iaid = *((uint32_t *) &packet[src_offset]);
                break;
              }
              default:
                break;
              }
              src_offset += opt_len;
            }
            #pragma endregion
            dhcpv6_hdr *reply_dhcpv6 =
                (dhcpv6_hdr *)&output[curr_offset];
            // TODO（100 行）
            #pragma region SetDHCPHDR
            // 如果是 DHCPv6 Solicit，说明客户端想要寻找一个 DHCPv6 服务器
            // 生成一个 DHCPv6 Advertise 并发送
            if(dhcpv6->msg_type == DHCPV6_MSG_SOLICIT) {
              // Refer to section 18.3.1. Receipt of Solicit Messages
              // Also refer to 18.3.9
              reply_dhcpv6->msg_type = DHCPV6_MSG_ADVERTISE;
            }
            // 如果是 DHCPv6 Request，说明客户端想要获取动态 IPv6 地址
            // 生成一个 DHCPv6 Reply 并发送
            else if(dhcpv6->msg_type == DHCPV6_MSG_REQUEST) {
              reply_dhcpv6->msg_type = DHCPV6_MSG_REPLY;
            } else {
              assert(false); // Impossible
            }
            // 响应的 Transaction ID 与 DHCPv6 Solicit/Request 一致。
            reply_dhcpv6->transaction_id_hi = dhcpv6->transaction_id_hi;
            reply_dhcpv6->transaction_id_lo = dhcpv6->transaction_id_lo;
            curr_offset += sizeof(dhcpv6_hdr);
            #pragma endregion

            // 响应的 DHCPv6 Advertise 和 DHCPv6 Reply
            // 都包括如下的 Option：
            #pragma region FillServerID
            // 1. Server Identifier：根据本路由器在本接口上的 MAC 地址生成。
            //    - https://www.rfc-editor.org/rfc/rfc8415.html#section-21.3
            dhcpv6_opt_hdr *opthdr = (dhcpv6_opt_hdr *) &output[curr_offset];
            const uint16_t serv_id_optsize = sizeof(dhcpv6_duid_hdr) + sizeof(uint32_t) + sizeof(ether_addr);
            
            //    - Option Code: 2
            //    - Option Length: 14
            opthdr->option_code = htons(DHCPV6_OPT_SERVERID);
            opthdr->option_len = htons(serv_id_optsize);
            curr_offset += sizeof(dhcpv6_opt_hdr);

            dhcpv6_duid_hdr *server_duid_hdr = (dhcpv6_duid_hdr *) &output[curr_offset];
            //    - DUID Type: 1 (Link-layer address plus time)
            //    - Hardware Type: 1 (Ethernet)
            server_duid_hdr->type = htons(DUID_LLT);
            server_duid_hdr->hardware = htons(ARPHRD_ETHER);
            curr_offset += sizeof(dhcpv6_duid_hdr);

            uint32_t* duid_time = (uint32_t *) &output[curr_offset];
            //    - DUID Time: 0
            *duid_time = 0;
            curr_offset += sizeof(uint32_t);
            
            ether_addr port_mac;
            HAL_GetInterfaceMacAddress(if_index, &port_mac);
            ether_addr *serv_addr = (ether_addr *) &output[curr_offset];
            //    - Link layer address: MAC Address
            *serv_addr = port_mac;
            curr_offset += sizeof(ether_addr);
            #pragma endregion
            #pragma region FillClientID
            // 2. Client Identifier
            //    - https://www.rfc-editor.org/rfc/rfc8415.html#section-21.2
            opthdr = (dhcpv6_opt_hdr *) &output[curr_offset];
            //    - Option Code: 1
            opthdr->option_code = htons(DHCPV6_OPT_CLIENTID);
            //    - Option Length: 和 Solicit/Request 中的 Client Identifier
            //    一致
            opthdr->option_len = htons(client_duid_len);
            curr_offset += sizeof(dhcpv6_opt_hdr);
            //    - DUID: 和 Solicit/Request 中的 Client Identifier 一致
            for(int i = 0; i < client_duid_len; ++i) {
              output[i + curr_offset] = client_duid[i];
            } 
            curr_offset += client_duid_len;
            #pragma endregion
            #pragma region FillIANA
            // 3. Identity Association for Non-temporary
            // Address：记录服务器将会分配给客户端的 IPv6 地址。
            //    - https://www.rfc-editor.org/rfc/rfc8415.html#section-21.4
            dhcpv6_opt_iana_hdr *iana_hdr = (dhcpv6_opt_iana_hdr *) &output[curr_offset];
            //    - Option Code: 3
            iana_hdr->opts.option_code = htons(DHCPV6_OPT_IA_NA); 
            const uint32_t iana_len = sizeof(dhcpv6_opt_iana_hdr) - sizeof(dhcpv6_opt_hdr) + sizeof(dhcpv6_opt_iaaddr_hdr);
            //    - Option Length: 40
            iana_hdr->opts.option_len = htons(iana_len);
            //    - IAID: 和 Solicit/Request 中的 Identity Association for
            //    Non-temporary Address 一致
            iana_hdr->iaid = iaid;
            //    - T1: 0
            iana_hdr->t1 = 0;
            //    - T2: 0
            iana_hdr->t2 = 0;
            curr_offset += sizeof(dhcpv6_opt_iana_hdr);
            //    - IA_NA options:
            //      - https://www.rfc-editor.org/rfc/rfc8415.html#section-21.6
            dhcpv6_opt_iaaddr_hdr *iaaddr_hdr = (dhcpv6_opt_iaaddr_hdr *) &output[curr_offset];
            //      - Option code: 5 (IA address)
            iaaddr_hdr->opts.option_code = htons(DHCPV6_OPT_IAADDR);
            //      - Length: 24
            iaaddr_hdr->opts.option_len = htons(sizeof(dhcpv6_opt_iaaddr_hdr) - sizeof(dhcpv6_opt_hdr));
            //      - IPv6 Address: fd00::1:2 ** switch to fd00::3:2 ?
            in6_addr assign_ip;
            get_new_ip(&assign_ip);
            iaaddr_hdr->ip = inet6_pton("fd00::1:2");//assign_ip;
            //      - Preferred lifetime: 54000s
            iaaddr_hdr->pref_lft = ntohl(54000);
            //      - Valid lifetime: 86400s
            iaaddr_hdr->valid_lft = ntohl(86400);
            curr_offset += sizeof(dhcpv6_opt_iaaddr_hdr);
            #pragma endregion
            #pragma region WriteDNS
            // 4. DNS recursive name server：包括两个 DNS 服务器地址
            // 2402:f000:1:801::8:28 和 2402:f000:1:801::8:29。
            //    - https://www.rfc-editor.org/rfc/rfc3646#section-3
            opthdr = (dhcpv6_opt_hdr *) &output[curr_offset];
            //    - Option Code: 23
            opthdr->option_code = htons(DHCPV6_OPT_DNS_SERVERS);
            //    - Option Length: 32
            opthdr->option_len = htons(DNS_CNT * sizeof(in6_addr));
            curr_offset += sizeof(dhcpv6_opt_hdr);
            
            //    - DNS: 2402:f000:1:801::8:28 <-- THU Shoool DNS IP address
            //    - DNS: 2402:f000:1:801::8:29
            in6_addr *dns_addr = (in6_addr *) &output[curr_offset];
            for(int i = 0; i < DNS_CNT; ++i) {
              dns_addr[i] = dns_addrs[i];
            }
            curr_offset += DNS_CNT * sizeof(in6_addr);
            #pragma endregion
            // 根据 DHCPv6 消息长度，计算 UDP 和 IPv6 头部中的长度字段
            
            uint16_t ip_len = curr_offset;
            uint16_t udp_len = ip_len - sizeof(ip6_hdr);

            udphdr *reply_udp = (udphdr *)&output[sizeof(ip6_hdr)];
            reply_udp->uh_sport = htons(547); // src port
            reply_udp->uh_dport = htons(546); // dst port
            reply_udp->uh_ulen = htons(udp_len);            
            // 构造响应的 IPv6 头部
            // 源 IPv6 地址应为 Link Local 地址
            ether_addr mac_addr;
            HAL_GetInterfaceMacAddress(if_index, &mac_addr);
            in6_addr self_link_local = eui64(mac_addr);
            assemble_IP6_hdr(output, self_link_local, ip6->ip6_src, ip_len, IPPROTO_UDP);
            validateAndFillChecksum(output, ip_len);

            HAL_SendIPPacket(if_index, output, ip_len, src_mac);
          }
        }
      } else if (ip6->ip6_nxt == IPPROTO_ICMPV6) {
        // TODO（1 行） -- Done
        // 如果是 ICMPv6 packet
        // 检查是否是 Router Solicitation
        
        icmp6_hdr *icmp6 = (icmp6_hdr *)&packet[sizeof(ip6_hdr)];
        if (icmp6->icmp6_type == ND_ROUTER_SOLICIT) {
          // TODO（70 行） -- Done
          const char *read_src_mac = ether_ntoa(src_mac);
          const char *read_dst_mac = ether_ntoa(dst_mac);
          const char *read_src_ip = inet6_ntoa(ip6->ip6_src); 
          const char *read_dst_ip = inet6_ntoa(ip6->ip6_dst);
          //fprintf(stderr, "Packet from MAC %s, dst MAC %s\n", read_src_mac, read_dst_mac);
          //fprintf(stderr, "Packet from IP %s, dst IP %s\n", read_src_ip, read_dst_ip);
          // 如果是 Router Solicitation，生成一个 Router Advertisement 并发送
          uint8_t *dump = new uint8_t[MIN_MTU];
          // ICMPv6 的各字段要求如下：
          // https://www.rfc-editor.org/rfc/rfc4861#section-4.2
          // 其 Type 是 Router Advertisement，Code 是 0
          size_t curr_offset = sizeof(ip6_hdr);
          nd_router_advert *nd_advert = (nd_router_advert *)(dump + curr_offset);
          icmp6_hdr *icmp_header = &(nd_advert->nd_ra_hdr);
          icmp_header->icmp6_type = ND_ROUTER_ADVERT;
          icmp_header->icmp6_code = 0;
          // Cur Hop Limit 设为 64
          // Cur hop limit, you may also set as 128 for windows NT platforms.
          icmp_header->icmp6_data8[0] = 64; 
          // M（Managed address configuration）和 O（Other configuration）设为 1
          // Note that O field is "redundant"
          icmp_header->icmp6_data8[1] = 192; // 0b 1100 0000
          // Router Lifetime 设为 210s --> Why?
          icmp_header->icmp6_data16[1] = htons(210); // 1800 is once observed in Wireshark
          // Reachable Time 和 Retrans Timer 设为 0ms

          nd_advert->nd_ra_reachable = 0;  // not specified
          nd_advert->nd_ra_retransmit = 0; // not specified
          curr_offset += sizeof(nd_router_advert);
          // 需要附上两个 ICMPv6 Option：
          
          // 1. Source link-layer address：内容是本路由器在本接口上的 MAC 地址
          //    - Type: 1
          //    - Length: 1
          //    - Link-layer address: MAC 地址
          nd_opt_hdr *src_info = (nd_opt_hdr *)(dump + curr_offset);
          src_info->nd_opt_type = ND_OPT_SOURCE_LINKADDR;
          src_info->nd_opt_len = 1;
          curr_offset += sizeof(nd_opt_hdr);
          ether_addr *src_addr = (ether_addr *)(dump + curr_offset);

          
          // 源 IPv6 地址是本路由器在本接口上的 Link Local 地址
          in6_addr link_local;
          ether_addr if_mac;
          HAL_GetInterfaceMacAddress(if_index, &if_mac);
          *src_addr = if_mac;
          curr_offset += sizeof(ether_addr);


          // 2. MTU：1500
          //    - Type: 5
          //    - Length: 1
          //    - MTU: 1500
          nd_opt_mtu *mtu_info = (nd_opt_mtu *)(dump + curr_offset);
          mtu_info->nd_opt_mtu_type = ND_OPT_MTU;
          mtu_info->nd_opt_mtu_len = 1;
          mtu_info->nd_opt_mtu_reserved = 0;
          mtu_info->nd_opt_mtu_mtu = htonl(1500);
          curr_offset += sizeof(nd_opt_mtu);

          link_local = eui64(if_mac);
          // 目的 IPv6 地址是 ff02::1
          // IPv6 头部的 Hop Limit 是 255 ** Refer to RFC-4861 section 4.2
          ip6_hdr *ip_header = (ip6_hdr *)dump;
          in6_addr all_multicast = inet6_pton("ff02::1");
          assemble_IP6_hdr(dump, link_local, all_multicast, curr_offset, IPPROTO_ICMPV6);
          validateAndFillChecksum(dump, 0);
          HAL_SendIPPacket(if_index, dump, curr_offset, src_mac);
          delete [] dump;
        }
      }
      continue;
    } else {
      // 目标地址不是我，考虑转发给下一跳
      // 检查是否是组播地址（ff00::/8），不需要转发组播分组
      if (ip6->ip6_dst.s6_addr[0] == 0xff) {
        printf("Don't forward multicast packet to %s\n",
               inet6_ntoa(ip6->ip6_dst));
        continue;
      }
      //fprintf(stderr, "Packet from MAC %s, dst MAC %s\n", ether_ntoa(src_mac), ether_ntoa(dst_mac));
      //fprintf(stderr, "Packet received from IP %s, fwd to IP %s\n", inet6_ntoa(ip6->ip6_src), inet6_ntoa(ip6->ip6_dst));
      // 检查 TTL（Hop Limit）是否小于或等于 1
      uint8_t ttl = ip6->ip6_hops;
      if (ttl <= 1) {
        // 可选功能，如果实现了对调试会有帮助
        // 发送 ICMP Time Exceeded 消息
        uint8_t *dump = new uint8_t[MIN_MTU];

        icmp6_hdr *icmp_header = (icmp6_hdr *)(dump + sizeof(ip6_hdr));
        icmp_header->icmp6_type = ICMP6_TIME_EXCEEDED;
        icmp_header->icmp6_code = ICMP6_TIME_EXCEED_TRANSIT;
        icmp_header->icmp6_pptr = 0;
        
        // 将接受到的 IPv6 packet 附在 ICMPv6 头部之后。
        // 如果长度大于 1232 字节，则取前 1232 字节：
        // 1232 = IPv6 Minimum MTU(1280) - IPv6 Header(40) - ICMPv6 Header(8)
        uint8_t *payload = dump + sizeof(ip6_hdr) + sizeof(icmp6_hdr);
        int n_payload = res < icmp_max_size ? res : icmp_max_size;
        for (int it = 0; it < n_payload; ++it)
        {
          payload[it] = packet[it];
        }
        
        // 意味着发送的 ICMP Time Exceeded packet 大小不大于 IPv6 Minimum MTU
        // 不会因为 MTU 问题被丢弃。
        // 详见 RFC 4443 Section 3.3 Time Exceeded Message
        int packet_size = n_payload + sizeof(icmp6_hdr) + sizeof(ip6_hdr);
        assemble_IP6_hdr(dump, addrs[if_index], ip6->ip6_src, packet_size, IPPROTO_ICMPV6, 64);
        
        // 计算 Checksum 后由自己的 IPv6 地址发送给源 IPv6 地址。
        validateAndFillChecksum(dump, 0);
        HAL_SendIPPacket(if_index, dump, packet_size, src_mac);
        delete[] dump;
      } else {
        // 转发给下一跳
        // 按最长前缀匹配查询路由表
        in6_addr nexthop;
        uint32_t dest_if;
        if (prefix_query(ip6->ip6_dst, &nexthop, &dest_if)) {
          // 找到路由
          ether_addr dest_mac;
          // 如果下一跳为全 0，表示的是直连路由，目的机器和本路由器可以直接访问
          if (nexthop == in6_addr{0}) {
            nexthop = ip6->ip6_dst;
          }
          if (HAL_GetNeighborMacAddress(dest_if, nexthop, &dest_mac) == 0) {
            // 在 NDP 表中找到了下一跳的 MAC 地址
            // TTL-1
            ip6->ip6_hops--;

            // 转发出去
            memcpy(output, packet, res);
            HAL_SendIPPacket(dest_if, output, res, dest_mac);
          } else {
            // 没有找到下一跳的 MAC 地址
            // 本实验中可以直接丢掉，等对方回复 NDP 之后，再恢复正常转发。
            printf("Nexthop ip %s is not found in NDP table\n",
                   inet6_ntoa(nexthop));
          }
        } else {
          // 没有找到路由
          // 可选功能，如果实现了对调试会有帮助
          // 发送 ICMPv6 Destination Unreachable 消息
          // 要求与上面发送 ICMPv6 Time Exceeded 消息一致
          // 详见 RFC 4443 Section 3.1 Destination Unreachable Message
          // 计算 Checksum 后由自己的 IPv6 地址发送给源 IPv6 地址。
          uint8_t *dump = new uint8_t[MIN_MTU];

           // FiLL ICMPv6 Header
          icmp6_hdr *icmp_header = (icmp6_hdr *)(dump + sizeof(ip6_hdr));
          icmp_header->icmp6_type = ICMP6_DST_UNREACH;
          // Code 取 0，表示 No route to destination
          icmp_header->icmp6_code = ICMP6_DST_UNREACH_NOROUTE;
          icmp_header->icmp6_pptr = 0;
          
          // 将接受到的 IPv6 packet 附在 ICMPv6 头部之后。
          uint8_t *payload = dump + sizeof(ip6_hdr) + sizeof(icmp6_hdr);
          int n_payload = res < icmp_max_size ? res : icmp_max_size;
          for (int it = 0; it < n_payload; ++it)
          {
            payload[it] = packet[it];
          }

          int packet_size = n_payload + sizeof(icmp6_hdr) + sizeof(ip6_hdr);
          assemble_IP6_hdr(dump, addrs[if_index], ip6->ip6_src, packet_size, IPPROTO_ICMPV6, 64);
          validateAndFillChecksum(dump, 0);
          HAL_SendIPPacket(if_index, dump, packet_size, src_mac);
          delete[] dump;

          printf("Destination IP %s not found in routing table",
                 inet6_ntoa(ip6->ip6_dst));
          printf(" and source IP is %s\n", inet6_ntoa(ip6->ip6_src));
        }
      }
    }
  }
  return 0;
}
