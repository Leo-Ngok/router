#include "checksum.h"
#include <assert.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

static int pseudo_header_sum(ip6_hdr *header, int protocol) {
  int sum = 0;
  auto src = header->ip6_src, dst = header->ip6_dst;
  for(int ii = 0; ii < 16; ii += 2) {
    int tt = src.s6_addr[ii];
    tt = (tt << 8) + src.s6_addr[ii + 1]; 
    sum += tt;
  }
  for(int ii = 0; ii < 16; ii += 2) {
    int tt = dst.s6_addr[ii];
    tt = (tt << 8) + dst.s6_addr[ii + 1]; 
    sum += tt;
  }
  sum += protocol; // next header number
  return sum;
}

int payload_sum(uint8_t *payload, size_t len){
  int ii = 0, sum = 0;
  if(len == 0) return 0;
  for( ;ii < len - 1; ii += 2) {
    int tt = payload[ii];
    tt = (tt << 8) + payload[ii + 1];
    sum += tt;
  }
  if(len & 1) sum += ((int)payload[len - 1]) << 8;
  return sum;
}

bool validateAndFillChecksum(uint8_t *packet, size_t len) {
  // TODO
  struct ip6_hdr *ip6 = (struct ip6_hdr *)packet;

  // check next header
  uint8_t nxt_header = ip6->ip6_nxt;
  if (nxt_header == IPPROTO_UDP) { // 17
    // UDP
    // fprintf(stderr, "UDP packet detected\n");
    struct udphdr *udp = (struct udphdr *)&packet[sizeof(struct ip6_hdr)];
    // length: udp->uh_ulen
    // checksum: udp->uh_sum

    /* Step one: Calculate header sum */
    int sum = pseudo_header_sum(ip6, 0x11);
    sum += ntohs(udp->uh_ulen);

    /* Step two: calculate payload sum */
    // calculate udp header
    sum += ntohs(udp->uh_dport);
    sum += ntohs(udp->uh_sport);
    sum += ntohs(udp->uh_ulen);
    // calculate udp payload
    auto *payload_ptr = packet + sizeof(struct ip6_hdr) + 8;
    int n = ntohs(udp->uh_ulen) - 8;
    sum += payload_sum(payload_ptr, n);

    sum = (sum & 0xffff) + (sum >> 16);
    sum ^= 0xffff;
    if(sum == 0) sum = 0xffff;
    // fprintf(stderr, "checksum is 0x%x\n", sum);
    uint16_t old_chksum = ntohs(udp->uh_sum);
    udp->uh_sum = htons((uint16_t)sum);
    if(old_chksum != sum) {
      return false;
    }
  } else if (nxt_header == IPPROTO_ICMPV6) {
    // ICMPv6
    // fprintf(stderr, "ICMP v6 packet detected\n");
    struct icmp6_hdr *icmp =
        (struct icmp6_hdr *)&packet[sizeof(struct ip6_hdr)];
    // length: len-sizeof(struct ip6_hdr)
    // checksum: icmp->icmp6_cksum
    /* Step one: Calculate header sum */
    int sum = pseudo_header_sum(ip6, 0x3a);
    /**
     * +---+--------+--------+--------+--------+
     * | 0 |       <src ipv6 address>          |
     * | 4 |                                   |
     * | 8 |                                   |
     * |12 |                                   |
     * +---+--------+--------+--------+--------+
     * |16 |        <dest ipv6 address>        |
     * |20 |                                   |
     * |24 |                                   |
     * |28 |                                   |
     * +---+--------+--------+--------+--------+
     * |32 |             ICMPv6 length         | (* Note: this field 
     * +---+--------+--------+--------+--------+ is considered as packet
     * |36 |      padding             | next=58| header, however it is 
     * +---+--------+--------+--------+--------+ transport layer dependent, 
     *                                           so it is not included in 
     *                                           header sum calculation)
    */ 
    int len = ntohs(ip6->ip6_plen);
    sum += len; // packet length, just add it back
    /* Step two: calculate payload sum */
    /**
     * +---+--------+--------+--------+--------+
     * | 0 |  type  |   code |    checksum     |
     * +---+--------+--------+--------+--------+
    */
    int tt = icmp->icmp6_type;
    sum += (tt << 8) + icmp->icmp6_code;
    auto *payload_ptr = packet + sizeof(struct ip6_hdr) + 4;
    sum += payload_sum(payload_ptr, len - 4);
    sum = (sum & 0xffff) + (sum >> 16);
    sum ^= 0xffff;
    if(sum == 0xffff) sum = 0;
    // fprintf(stderr, "checksum is 0x%x\n", sum);
    uint16_t old_chksum = ntohs(icmp->icmp6_cksum);
    if(old_chksum == 0xffff) old_chksum = 0;
    icmp->icmp6_cksum = htons((uint16_t) sum);
    if(old_chksum != sum) {
      return false;
    }
  } else {
    assert(false);
  }
  return true;
}
