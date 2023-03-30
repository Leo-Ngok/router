#include "lookup.h"
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <vector>

std::vector<RoutingTableEntry> IPEntries;
#ifdef _DEBUG_
static void display_address(in6_addr addr) {
  for(int k = 0; k < 16; ++k) {
    fprintf(stderr, "%02x", addr.s6_addr[k]);
    if((k & 1) && k != 15)
      fprintf(stderr, ":");
  }
  fprintf(stderr, "\n");
}
#endif
bool mask_equal(in6_addr addr, RoutingTableEntry entry) {
  in6_addr mask = len_to_mask(entry.len);
  in6_addr src_addr, dest_addr;
  for(int k = 0; k < 16; ++k) {
    if(mask.s6_addr[k] == 0) break;
    if((entry.addr.s6_addr[k] & mask.s6_addr[k]) 
    != (addr.s6_addr[k] & mask.s6_addr[k])){
      return false;
    }
  }
  return true;
}

void update(bool insert, const RoutingTableEntry entry) {
  /* Naive approach, just do linear search */
  auto item_it = IPEntries.end();
  for(auto it = IPEntries.begin(); it != IPEntries.end(); ++it) {
    if(mask_equal(it->addr, entry)) {
      if(entry.len == it->len) {
        item_it = it;
        break;
      }
    }
  }
  if(insert) {
    if(item_it != IPEntries.end()) {
      *item_it = entry;
    } else {
      IPEntries.push_back(entry);
    }
  } else {
    if(item_it != IPEntries.end())
      IPEntries.erase(item_it);
  }
  /* Advanced: Lulea algorithm. */
}

bool prefix_query(const in6_addr addr, in6_addr *nexthop, uint32_t *if_index) {
  /* Naive approach, just do linear search */
  auto item_it = IPEntries.end();
  int match_len = 0;
  for(auto it = IPEntries.begin(); it != IPEntries.end(); ++it) {
    if(mask_equal(addr, *it) ) {
      if(match_len < it->len || (it->len == 0 && match_len == 0)) {
        match_len = it->len;
        item_it = it;
      } 
    }
  }
  if(item_it != IPEntries.end()) {
    // Found.
    *nexthop = item_it->nexthop;
    *if_index = item_it->if_index;
    return true;
  } 
  return false;
}

int mask_to_len(const in6_addr mask) {
  int count = 0;
  bool end = false;

  for(int k = 0; k < 16; k++) {
    if(count == -1) break;
    auto octet = mask.s6_addr[k];

    // Handle the two trivial cases first.
    if(octet == 0xff) {
      count += 8;
    } else if(octet == 0x00) {
      end = true;
    } 
    // Only needs special care in this case.
    else {
      if(end) {
        count = -1; break; // ff 00 *1 case detected.
      }
      end = true;
      switch (octet)
      {
        // Only this 7 cases are possible.
      case 0x80: count++;    break; // 1000 0000
      case 0xc0: count += 2; break; // 1100 0000
      case 0xe0: count += 3; break; // 1110 0000
      case 0xf0: count += 4; break; // 1111 0000
      case 0xf8: count += 5; break; // 1111 1000
      case 0xfc: count += 6; break; // 1111 1100
      case 0xfe: count += 7; break; // 1111 1110
      // not possible
      default:   count = -1; break;
      }
    }
  }
  return count;
}

in6_addr len_to_mask(int len) {
  in6_addr addr = {0};
  int k = 0;
  while(len >= 8) {
    addr.s6_addr[k++] = 0xff;
    len -= 8; 
  }
  switch(len) {
    case 7:      addr.s6_addr[k] |= 1 << 1;
    case 6:      addr.s6_addr[k] |= 1 << 2;
    case 5:      addr.s6_addr[k] |= 1 << 3;
    case 4:      addr.s6_addr[k] |= 1 << 4;
    case 3:      addr.s6_addr[k] |= 1 << 5;
    case 2:      addr.s6_addr[k] |= 1 << 6;
    case 1:      addr.s6_addr[k] |= 1 << 7;
    default:     break;
  }
  return addr;
}

bool query(const in6_addr addr, uint8_t prefix_len, RoutingTableEntry *__entry) {
  for(auto it = IPEntries.begin(); it != IPEntries.end(); ++it) {
    if(it->addr == addr) {
      if((uint32_t) prefix_len == it->len) {
        *__entry = *it;
        return true;
      }
    }
  }
  return false;
}


std::vector<RoutingTableEntry>::iterator RTableBegin() {
  return IPEntries.begin();
}
std::vector<RoutingTableEntry>::iterator RTableEnd() {
  return IPEntries.end();
}

size_t TableSize() {
  return IPEntries.size();
}

