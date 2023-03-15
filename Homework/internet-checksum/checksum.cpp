#include "checksum.h"
#include <assert.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

// Checksum of pseudo IPv6 header.
// RFC 2460
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
 * |32 |          Payload length           |
 * +---+--------+--------+--------+--------+
 * |36 |          padding         |  next  |
 * +---+--------+--------+--------+--------+
 *
 */
/// @brief Checksum of pseudo IPv6 header.
/// @param header pointer to the IPv6 packet header
/// @return The sum of all consecutive 16 bits of the pseudo header.
/// @see RFC 2460
int pseudo_header_sum(ip6_hdr *header)
{
  int sum = 0;
  auto src = header->ip6_src, dst = header->ip6_dst;
  for (int ii = 0; ii < 16; ii += 2)
  {
    int tt = src.s6_addr[ii];
    tt = (tt << 8) + src.s6_addr[ii + 1];
    sum += tt;
  }
  for (int ii = 0; ii < 16; ii += 2)
  {
    int tt = dst.s6_addr[ii];
    tt = (tt << 8) + dst.s6_addr[ii + 1];
    sum += tt;
  }
  sum += ntohs(header->ip6_plen);
  sum += header->ip6_nxt; // next header number
  return sum;
}

/// @brief Checksum of contents of a packet, without considering any headers.
/// @param payload pointer to the base location of the payload.
/// @param len length of payload
/// @return Sum of all consecutive 16 bits.
int payload_sum(uint8_t *payload, size_t len)
{
  if (len == 0)
    return 0;
  int sum = 0;
  for (int ii = 0; ii < len - 1; ii += 2)
  {
    int tt = payload[ii];
    tt = (tt << 8) + payload[ii + 1];
    sum += tt;
  }
  if (len & 1)
    sum += ((int)payload[len - 1]) << 8;
  return sum;
}

bool validateAndFillChecksum(uint8_t *packet, size_t len)
{
  // TODO
  struct ip6_hdr *ip6 = (struct ip6_hdr *)packet;

  /* Step one: Calculate header sum */
  int sum = pseudo_header_sum(ip6);

  // check next header
  uint8_t nxt_header = ip6->ip6_nxt;
  if (nxt_header == IPPROTO_UDP)
  {
    // UDP
    // fprintf(stderr, "UDP packet detected\n");
    struct udphdr *udp = (struct udphdr *)&packet[sizeof(struct ip6_hdr)];
    // length: udp->uh_ulen
    // checksum: udp->uh_sum

    /* Step two: calculate payload sum */
    /**
     * RFC 768
     *  0      7 8     15 16    23 24    31
        +--------+--------+--------+--------+
        |     Source      |   Destination   |
        |      Port       |      Port       |
        +--------+--------+--------+--------+
        |                 |                 |
        |     Length      |    Checksum     |
        +--------+--------+--------+--------+
    */
    // calculate udp header
    sum += ntohs(udp->uh_dport);
    sum += ntohs(udp->uh_sport);
    sum += ntohs(udp->uh_ulen);

    // calculate udp payload
    auto *payload_ptr = packet + sizeof(ip6_hdr) + sizeof(udphdr);
    int n = ntohs(udp->uh_ulen) - sizeof(udphdr);
    sum += payload_sum(payload_ptr, n);

    // Final adjustments.
    sum = (sum & 0xffff) + (sum >> 16);
    sum ^= 0xffff;
    if (sum == 0)
      sum = 0xffff;

    // Check checksum consistency.
    // fprintf(stderr, "checksum is 0x%x\n", sum);
    uint16_t old_chksum = ntohs(udp->uh_sum);
    udp->uh_sum = htons((uint16_t)sum);
    if (old_chksum != sum)
    {
      return false;
    }
  }
  else if (nxt_header == IPPROTO_ICMPV6)
  {
    // ICMPv6
    struct icmp6_hdr *icmp =
        (struct icmp6_hdr *)&packet[sizeof(struct ip6_hdr)];
    // length: len-sizeof(struct ip6_hdr)
    // checksum: icmp->icmp6_cksum

    /* Step two: calculate payload sum */
    /**
     * RFC 4443
     * +---+--------+--------+--------+--------+
     * | 0 |  type  |   code |    checksum     |
     * +---+--------+--------+--------+--------+
     */

    // ICMP "header"
    int tt = icmp->icmp6_type;
    sum += (tt << 8) + icmp->icmp6_code;

    // ICMP "content" (actually it is part of header by definition)
    auto *payload_ptr = packet + sizeof(struct ip6_hdr) + 4;
    sum += payload_sum(payload_ptr, len - 4);

    // Final adjustments.
    sum = (sum & 0xffff) + (sum >> 16);
    sum ^= 0xffff;
    if (sum == 0xffff)
      sum = 0;

    // Check checksum consistency.
    // fprintf(stderr, "checksum is 0x%x\n", sum);
    uint16_t old_chksum = ntohs(icmp->icmp6_cksum);
    if (old_chksum == 0xffff)
      old_chksum = 0;
    icmp->icmp6_cksum = htons((uint16_t)sum);
    if (old_chksum != sum)
    {
      return false;
    }
  }
  else
  {
    assert(false);
  }
  return true;
}
