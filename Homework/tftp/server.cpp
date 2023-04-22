#include "checksum.h"
#include "common.h"
#include "eui64.h"
#include "lookup.h"
#include "protocol.h"
#include "router_hal.h"
#include "tftp.h"
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <vector>

uint8_t packet[2048];
uint8_t output[2048];

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
#elif defined(ROUTER_R2)
// 0: fd00::3:2/112
// 1: fd00::5:1/112
// 2: fd00::6:1/112
// 3: fd00::7:1/112
in6_addr addrs[N_IFACE_ON_BOARD] = {
    {0xfd, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
     0x00, 0x03, 0x00, 0x02},
    {0xfd, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
     0x00, 0x03, 0x00, 0x01},
    {0xfd, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
     0x00, 0x06, 0x00, 0x01},
    {0xfd, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
     0x00, 0x07, 0x00, 0x01},
};
// 默认网关：fd00::3:1
in6_addr default_gateway = {0xfd, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                            0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x00, 0x01};
#elif defined(ROUTER_PC2)
// 0: fd00::5:1/112
// 1: fd00::6:1/112
// 2: fd00::7:1/112
// 3: fd00::8:1/112
in6_addr addrs[N_IFACE_ON_BOARD] = {
    {0xfd, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
     0x00, 0x05, 0x00, 0x01},
    {0xfd, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
     0x00, 0x06, 0x00, 0x01},
    {0xfd, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
     0x00, 0x07, 0x00, 0x01},
    {0xfd, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
     0x00, 0x08, 0x00, 0x01},
};
// 默认网关：fd00::5:2
in6_addr default_gateway = {0xfd, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                            0x00, 0x00, 0x00, 0x00, 0x00, 0x05, 0x00, 0x02};
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

enum TransferState {
  // 正在传输
  InTransfer,
  // 传输完毕，等待最后一个 ACK
  LastAck,
};

struct transfer {
  // 读还是写
  bool is_read;
  // 服务端 TID
  uint16_t server_tid;
  // 客户端 TID
  uint16_t client_tid;
  // 客户端 IPv6 地址
  in6_addr client_addr;
  // 用于读/写的本地文件
  FILE *fp;
  // 传输状态
  TransferState state;
  // 最后一次传输的 Block 编号
  uint16_t last_block_number;
  // 最后一次传输的数据，用于重传
  uint8_t last_block_data[512];
  // 最后一次传输的数据长度
  size_t last_block_size;
};
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

std::vector<transfer> transfers;
static void send_tftp_packet(uint8_t *pkt_front, ether_addr &dstmac,
size_t len, transfer &curr_tf) {
  const int if_number = 0;
  const in6_addr src_addr = addrs[if_number];
  len += sizeof(ip6_hdr) + sizeof(udphdr) + sizeof(tftp_hdr);
  udphdr *out_udp = (udphdr *) &pkt_front[sizeof(ip6_hdr)];
  out_udp->uh_sport = htons(curr_tf.server_tid);
  out_udp->uh_dport = htons(curr_tf.client_tid);
  out_udp->uh_ulen  = htons(len - sizeof(ip6_hdr));

  ip6_hdr *in_ip6hdr = (ip6_hdr *) &packet[0];
  assemble_IP6_hdr(pkt_front, in_ip6hdr->ip6_dst, curr_tf.client_addr, len, IPPROTO_UDP);
  validateAndFillChecksum(pkt_front, 0);
  HAL_SendIPPacket(if_number, pkt_front, len, dstmac);
}
int main(int argc, char *argv[]) {
  // 记录当前所有的传输状态

  // 初始化 HAL
  int res = HAL_Init(1, addrs);
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
      printf("Received invalid ipv6 packet (%d < %lu)\n", res, sizeof(ip6_hdr));
      continue;
    }
    uint16_t plen = ntohs(ip6->ip6_plen);
    if (res < plen + sizeof(ip6_hdr)) {
      printf("Received invalid ipv6 packet (%d < %d + %lu)\n", res, plen,
             sizeof(ip6_hdr));
      continue;
    }

    // 检查 IPv6 头部目的地址是否为我自己
    bool dst_is_me = false;
    for (int i = 0; i < N_IFACE_ON_BOARD; i++) {
      if (memcmp(&ip6->ip6_dst, &addrs[i], sizeof(in6_addr)) == 0) {
        dst_is_me = true;
        break;
      }
    }

    if (dst_is_me) {
      // 目的地址是我，按照类型进行处理

      // 检查 checksum 是否正确
      if (ip6->ip6_nxt == IPPROTO_UDP) {
        if (!validateAndFillChecksum(packet, res)) {
          printf("Received packet with bad checksum\n");
          continue;
        }
      }

      if (ip6->ip6_nxt == IPPROTO_UDP) {
        // TODO（1 行） -- DONE
        // 检查 UDP 端口，判断是否为 TFTP message
        udphdr *udp = (udphdr *)&packet[sizeof(ip6_hdr)];
        if (htons(udp->uh_dport) == 69) {
          // TODO（1 行） -- Done
          // 新连接
          // 判断 Opcode 是否为 RRQ 或 WRQ
          tftp_hdr *tftp =
              (tftp_hdr *)&packet[sizeof(ip6_hdr) + sizeof(udphdr)];
          uint16_t opcode = ntohs(tftp->opcode);
          if (opcode == 1 || opcode == 2) {
            // TODO（6 行）
            // 解析 Filename（文件名）和 Mode（传输模式）
            char file_name[1024];
            strcpy(file_name, (const char *) &packet[sizeof(ip6_hdr) + sizeof(udphdr) + sizeof(opcode)]);

            // 生成一个新的传输状态，将会插入到 transfers 数组中
            struct transfer new_transfer;

            // TODO（3 行）-- Done
            // 客户端 TID 等于客户端发送的 UDP 报文的 UDP 源端口，
            new_transfer.client_tid = ntohs(udp->uh_sport);
            // 在 49152-65535 范围中随机生成服务端 TID，
            new_transfer.server_tid = 49152 + (rand() % 16384);
            // 记录下客户端的 IPv6 地址。
            new_transfer.client_addr = ip6->ip6_src;
            // 此后服务端向客户端发送的 UDP 数据报，
            // 其源 UDP 端口都为服务端 TID，
            // 其目的 UDP 端口都为客户端 TID，
            // 其源 IPv6 地址为客户端发送的请求中的目的 IPv6 地址，
            // 其目的 IPv6 地址为客户端发送的请求中的源 IPv6 地址。
            
            if (opcode == 1) {
              // 如果操作是读取文件
              new_transfer.is_read = true;

              // TODO（1 行） -- Done
              // 尝试打开文件，判断文件是否存在
              new_transfer.fp = fopen(file_name, "rb");
              if (new_transfer.fp != nullptr) {
                // 如果文件存在，则发送文件的第一个块。

                // 从文件中读取最多 512 字节的数据
                uint8_t block[512];
                size_t block_size = fread(block, 1, 512, new_transfer.fp);

                // 把最后一次发送的块记录下来
                // 用于重传
                new_transfer.last_block_number = 1;
                memcpy(new_transfer.last_block_data, block, block_size);
                new_transfer.last_block_size = block_size;

                // 构造响应的 IPv6 头部
                // IPv6 header
                ip6_hdr *reply_ip6 = (ip6_hdr *)&output[0];
                // flow label
                reply_ip6->ip6_flow = 0;
                // version
                reply_ip6->ip6_vfc = 6 << 4;
                // next header
                reply_ip6->ip6_nxt = IPPROTO_UDP;
                // hop limit
                reply_ip6->ip6_hlim = 255;
                // src ip
                reply_ip6->ip6_src = ip6->ip6_dst;
                // dst ip
                reply_ip6->ip6_dst = ip6->ip6_src;

                udphdr *reply_udp = (udphdr *)&output[sizeof(ip6_hdr)];
                // src port
                reply_udp->uh_sport = htons(new_transfer.server_tid);
                // dst port
                reply_udp->uh_dport = htons(new_transfer.client_tid);

                uint8_t *reply_tftp =
                    (uint8_t *)&output[sizeof(ip6_hdr) + sizeof(udphdr)];
                uint16_t tftp_len = 0;

                // opcode = 0x03(data)
                reply_tftp[tftp_len++] = 0x00;
                reply_tftp[tftp_len++] = 0x03;

                // # block = 1
                reply_tftp[tftp_len++] = 0x00;
                reply_tftp[tftp_len++] = 0x01;

                memcpy(&reply_tftp[tftp_len], block, block_size);
                tftp_len += block_size;

                // 根据 TFTP 消息长度，计算 UDP 和 IPv6 头部中的长度字段
                uint16_t udp_len = tftp_len + sizeof(udphdr);
                uint16_t ip_len = udp_len + sizeof(ip6_hdr);
                reply_udp->uh_ulen = htons(udp_len);
                reply_ip6->ip6_plen = htons(udp_len);
                validateAndFillChecksum(output, ip_len);

                HAL_SendIPPacket(if_index, output, ip_len, src_mac);

                // 如果第一个块大小等于 512，说明还有后续的数据需要传输，
                // 进入 InTransfer 状态；
                // 如果第一个块大小已经小于 512，则进入 LastAck 状态，
                // 表示需要等待客户端发送最后一次 ACK
                if (block_size == 512) {
                  new_transfer.state = InTransfer;
                } else {
                  new_transfer.state = LastAck;
                }

                // 记录当前传输到 transfers 数组
                transfers.push_back(new_transfer);
              } else {
                // TODO（50 行） -- Done
                // 如果文件不存在，则发送一个错误响应，
                // 其 ErrorCode 为 1，ErrMsg 为 File not found。
                size_t curr_offset = sizeof(in6_addr) + sizeof(udphdr);
                tftp_hdr *out_tftp = (tftp_hdr *) &output[curr_offset];
                out_tftp->error_code = htons(1);
                out_tftp->opcode = ntohs(5);
                curr_offset += sizeof(tftp_hdr);
                strcpy((char *) &output[curr_offset], "File not found");
                send_tftp_packet(output, src_mac, 15, new_transfer);
              }

            } else if (opcode == 2) {
              // 如果操作是写入文件

              new_transfer.is_read = false;
              new_transfer.fp = fopen(file_name, "r");
              if (new_transfer.fp) {
                // TODO（50 行） -- Done
                // 文件已经存在，则发送一个错误响应，
                // 其 ErrorCode 为 6，ErrMsg 为 File already exists。
                size_t curr_offset = sizeof(in6_addr) + sizeof(udphdr);
                tftp_hdr *out_tftp = (tftp_hdr *) &output[curr_offset];
                out_tftp->error_code = htons(6);
                out_tftp->opcode = ntohs(5);
                curr_offset += sizeof(tftp_hdr);
                strcpy((char *) &output[curr_offset], "File already exists");
                send_tftp_packet(output, src_mac, 20, new_transfer);
              } else {
                // 可选功能：如果文件无法写入，也汇报错误
                new_transfer.fp = fopen(file_name, "wb");
                assert(new_transfer.fp);

                // TODO（40 行） -- Done
                // 文件不存在，则发送一个 ACK（Block Number = 0），
                // 告诉客户端可以开始发送了。
                size_t curr_offset = sizeof(ip6_hdr) + sizeof(udphdr);
                tftp_hdr *out_tftp = (tftp_hdr *) &output[curr_offset];
                out_tftp->opcode = htons(4);
                out_tftp->block_number = 0;

                send_tftp_packet(output, src_mac, 0, new_transfer);
                new_transfer.last_block_number = 0;
                transfers.push_back(new_transfer);
              }
            }
          }
        } else {
          tftp_hdr *tftp =
              (tftp_hdr *)&packet[sizeof(ip6_hdr) + sizeof(udphdr)];
          uint16_t opcode = ntohs(tftp->opcode);
          uint16_t block_number = ntohs(tftp->block_number);
          for (int i = 0; i < transfers.size(); i++) {
            transfer &current_transfer = transfers[i];
            // TODO（3 行） -- Done
            // 在 `transfers` 数组中找到唯一匹配的传输，满足：
            // 源 UDP 端口等于客户端 TID 且
            // 目的 UDP 端口等于服务端 TID 且
            // 源 IPv6 地址等于客户端 IPv6 地址。

            if (current_transfer.client_addr == ip6->ip6_src && 
                current_transfer.client_tid == ntohs(udp->uh_sport) &&
                current_transfer.server_tid == ntohs(udp->uh_dport)) {
              if (current_transfer.is_read) {
                // TODO（1 行） -- Done
                // 如果传输的操作是读取，判断 Opcode 是否为 ACK。
                if (opcode == 4) {
                  // TODO（1 行） -- Done
                  // 如果是 ACK，检查 Block 编号
                  if (block_number == current_transfer.last_block_number) {
                    // TODO（1 行） -- Done
                    // 如果和最后一次发送的 Block 编号相等
                    // 判断当前状态
                    if (current_transfer.state == InTransfer) {
                      // TODO（60 行） -- Done
                      // 如果是 InTransfer 状态，说明文件还没有传输完成，
                      // 则从文件中读取下一个 Block 并发送；
                      block_number++;
                      uint8_t *payload = &output[sizeof(ip6_hdr) + sizeof(udphdr) + sizeof(tftp_hdr)];
                      size_t bytes_read = fread(payload, sizeof(uint8_t), 512, current_transfer.fp);
                      // Encapsulates packet
                      tftp_hdr *out_tftp = (tftp_hdr *) &output[sizeof(ip6_hdr) + sizeof(udphdr)];
                      out_tftp->block_number = htons(block_number);
                      out_tftp->opcode = 3;

                      send_tftp_packet(output, src_mac, bytes_read, current_transfer);
                      // 如果读取的字节数不足 512，则进入 LastAck 状态
                      if(bytes_read < 512)
                        current_transfer.state = LastAck;

                      memcpy(current_transfer.last_block_data, payload, bytes_read);
                      current_transfer.last_block_number = block_number;
                      current_transfer.last_block_size = bytes_read;
                    } else if (current_transfer.state == LastAck) {
                      // 如果是 LastAck 状态，说明这次 TFTP 读取请求已经完成，
                      // 关闭文件，
                      // 从 transfers 数组中移除当前传输
                      fclose(current_transfer.fp);
                      transfers.erase(transfers.begin() + i);
                    }
                  } else {
                    // TODO（50 行） -- Done
                    // 如果和最后一次发送的 Block
                    // 不相等（例如出现了丢包或者乱序等问题），
                    // 则重新发送最后一个 Block。
                    uint8_t *payload = &output[sizeof(ip6_hdr) + sizeof(udphdr) + sizeof(tftp_hdr)];
                    memcpy(payload, current_transfer.last_block_data, current_transfer.last_block_size);
                    // Encapsulates packet
                    tftp_hdr *out_tftp = (tftp_hdr *) &output[sizeof(ip6_hdr) + sizeof(udphdr)];
                    out_tftp->block_number = htons(current_transfer.last_block_number);
                    out_tftp->opcode = 3;

                    send_tftp_packet(output, src_mac, current_transfer.last_block_size, current_transfer);
                  }
                }
              } else {
                // 如果传输的操作是写入，判断 Opcode 是否为 DATA。
                if (opcode == 0x03) {
                  // TODO（1 行） -- Done
                  // 如果 Opcode 是 DATA，检查 Block 编号
                  // 如果是最后一次传输的 Block 编号加一，说明是新传输的数据
                  if (block_number - current_transfer.last_block_number == 1) {
                    // TODO（50 行）
                    // 那么写入块到文件中，并发送 ACK。
                    uint16_t block_size = ntohs(udp->uh_ulen) - sizeof(udphdr) - sizeof(tftp_hdr);
                    uint8_t *payload = packet + sizeof(ip6_hdr) + sizeof(udphdr) + sizeof(tftp_hdr);
                    fwrite(payload, sizeof(payload[0]), block_size, current_transfer.fp);

                    current_transfer.last_block_number += 1;

                    // 如果块的大小小于 512，说明这是最后一个块，写入文件后，
                    // 关闭文件，发送 ACK，
                    // 从 transfers 数组中移除当前传输
                    if (block_size < 512) {
                      fclose(current_transfer.fp);
                      printf("File received \n");
                      transfers.erase(transfers.begin() + i);
                      tftp_hdr *out_tftp = (tftp_hdr *) &output[sizeof(ip6_hdr) + sizeof(udphdr)];
                      out_tftp->opcode = htons(4);
                      out_tftp->block_number = tftp->block_number;
                      send_tftp_packet(output, src_mac, 0, current_transfer);
                    }
                  }
                }
              }
              break;
            }
          }
        }
      }
      continue;
    } else {
      // 目标地址不是我，忽略
    }
  }
  return 0;
}
