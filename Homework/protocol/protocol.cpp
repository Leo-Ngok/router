#include "protocol.h"
#include "common.h"
#include "lookup.h"
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#define IPv6_ADDR_LEN 128
#define IPv6_ADDR_LEN_BYTES (IPv6_ADDR_LEN >> 3)

static void display_address(in6_addr addr) {
  for(int k = 0; k < 16; ++k) {
    fprintf(stderr, "%02x", addr.s6_addr[k]);
    if((k & 1) && k != 15)
      fprintf(stderr, ":");
  }
  fprintf(stderr, "\n");
}

RipngErrorCode disassemble(const uint8_t *packet, uint32_t len,
                         RipngPacket *output) {
  ip6_hdr *header = (ip6_hdr *) packet;

  // Step 1: Check for packet length
  if(len < sizeof(struct ip6_hdr) || 
  len - ntohs(header->ip6_plen) != sizeof(ip6_hdr)) {
    return RipngErrorCode::ERR_LENGTH;
  }
  
  uint16_t payload_len = header->ip6_plen;

  // Step 2: Check for protocol
  if(header->ip6_nxt != IPPROTO_UDP) {
    return RipngErrorCode::ERR_IPV6_NEXT_HEADER_NOT_UDP;
  }

  // Step 3: Check for UDP length consistency.
  udphdr *udp = (udphdr *)(packet + sizeof(ip6_hdr));
  if(payload_len != udp->len) {
    return RipngErrorCode::ERR_LENGTH;
  }

  // Step 4: Check Port number. Both of which MUST be 521.
  if(ntohs(udp->uh_dport) != 521 || ntohs(udp->uh_sport) != 521) {
    return RipngErrorCode::ERR_UDP_PORT_NOT_RIPNG;
  }

  // Step 5: Check if payload length is multiple of entry size
  size_t payload_size = ntohs(payload_len) - sizeof(udphdr) - sizeof(ripng_hdr);
  if(payload_size % sizeof(ripng_rte) != 0) {
    return RipngErrorCode::ERR_LENGTH;
  }

  // Step 6: Check RIPng header.
  ripng_hdr *ripng_header = (ripng_hdr*) (packet + sizeof(ip6_hdr) + sizeof(udphdr));
  uint8_t cmd = ripng_header->command;
  uint8_t ver = ripng_header->version;
  uint16_t padding = ripng_header->zero;
  if(cmd != 1 && cmd != 2) {
    return RipngErrorCode::ERR_RIPNG_BAD_COMMAND;
  }
  if(ver != 1) {
    return RipngErrorCode::ERR_RIPNG_BAD_VERSION;
  }
  if(padding != 0) {
    return RipngErrorCode::ERR_RIPNG_BAD_ZERO;
  }

  output->command = cmd;

  // Step 7: Check payload
  size_t count = payload_size / sizeof(ripng_rte);
  ripng_rte *entry = (ripng_rte *) (packet + sizeof(ip6_hdr) + sizeof(udphdr) + sizeof(ripng_hdr));
  output->numEntries = count;
  for(int k = 0; k < count; ++k) {
    if(entry->metric == 0xff) {
      // next hop
      if(entry->prefix_len != 0) {
        return RipngErrorCode::ERR_RIPNG_BAD_PREFIX_LEN;
      }
      if(entry->route_tag != 0) {
        return RipngErrorCode::ERR_RIPNG_BAD_ROUTE_TAG;
      }
    } else {
      if(entry->metric < 1 || entry->metric > 16) {
        return RipngErrorCode::ERR_RIPNG_BAD_METRIC;
      }
      if(entry->prefix_len > 128U) {
        return RipngErrorCode::ERR_RIPNG_BAD_PREFIX_LEN;
      }
      // TODO: Check prefix length field and prefix consistency
      //fprintf(stderr, "----------------\npayload prefix length: %u\nprefix:", entry->prefix_len);
      //display_address(entry->prefix_or_nh);
      in6_addr mask = len_to_mask(entry->prefix_len);
      for(int j = 0; j < 16; ++j) {
        if(entry->prefix_or_nh.s6_addr[j] & ~(char)mask.s6_addr[j] != 0) {
          return RipngErrorCode::ERR_RIPNG_INCONSISTENT_PREFIX_LENGTH;
        }
      }
    }
    output->entries[k] = *entry;
    entry++;
  }
  return RipngErrorCode::SUCCESS;
}

uint32_t assemble(const RipngPacket *ripng, uint8_t *buffer) {
  int n = 0;
  // RIPng header
  buffer[n++] = ripng->command;
  buffer[n++] = 1; // version
  buffer[n++] = 0;
  buffer[n++] = 0; // buffer zeroes
  for(int k = 0; k < ripng->numEntries; ++k) {
    auto entry = ripng->entries[k];
    for(int j = 0; j < IPv6_ADDR_LEN_BYTES; j++)
      buffer[n++] = entry.prefix_or_nh.s6_addr[j];
    buffer[n++] = entry.route_tag & 0xff;
    buffer[n++] = entry.route_tag >> 8;
    buffer[n++] = entry.prefix_len;
    buffer[n++] = entry.metric;
  }
  
  return n;
}