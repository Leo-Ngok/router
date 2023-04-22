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
#ifdef ROUTER_PC1
// 0: fd00::1:2/112
// 1: fd00::6:1/112
// 2: fd00::7:1/112
// 3: fd00::8:1/112
in6_addr addrs[N_IFACE_ON_BOARD] = {
    {0xfd, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
     0x00, 0x01, 0x00, 0x02},
    {0xfd, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
     0x00, 0x06, 0x00, 0x01},
    {0xfd, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
     0x00, 0x07, 0x00, 0x01},
    {0xfd, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
     0x00, 0x08, 0x00, 0x01},
};
// 默认网关：fd00::1:1
in6_addr default_gateway = {0xfd, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                            0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x01};
#elif defined(ROUTER_R2)
// 0: fd00::3:2/112
// 1: fd00::4:1/112
// 2: fd00::7:1/112
// 3: fd00::8:1/112
in6_addr addrs[N_IFACE_ON_BOARD] = {
    {0xfd, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
     0x00, 0x03, 0x00, 0x02},
    {0xfd, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
     0x00, 0x04, 0x00, 0x01},
    {0xfd, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
     0x00, 0x07, 0x00, 0x01},
    {0xfd, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
     0x00, 0x08, 0x00, 0x01},
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
// 默认网关：fd00::1:1
in6_addr default_gateway = {0xfd, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                            0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x01};
#endif

enum TransferState {
  // 初始状态
  Initial,
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
  // 服务端 IPv6 地址
  in6_addr server_addr;
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
static transfer *curr_tf;
static void send_tftp_packet(uint8_t *pkt_front, ether_addr &dstmac,
size_t len, bool init = false) {
  const int if_number = 0;
  const in6_addr src_addr = addrs[if_number];
  len += sizeof(ip6_hdr) + sizeof(udphdr) + sizeof(tftp_hdr);
  udphdr *out_udp = (udphdr *) &pkt_front[sizeof(ip6_hdr)];
  out_udp->uh_dport = htons(init ? 69 : curr_tf->server_tid);
  out_udp->uh_sport = htons(curr_tf->client_tid);
  out_udp->uh_ulen  = htons(len - sizeof(ip6_hdr));
  assemble_IP6_hdr(pkt_front, addrs[0], curr_tf->server_addr, len, IPPROTO_UDP);
  validateAndFillChecksum(pkt_front, 0);
  HAL_SendIPPacket(if_number, pkt_front, len, dstmac);
}
int main(int argc, char *argv[]) {
  // 记录当前的传输状态
  transfer current_transfer;
  curr_tf = &current_transfer;
  // 初始化 HAL
  int res = HAL_Init(0, addrs);
  if (res < 0) {
    return res;
  }

  // 插入直连路由
  // PC1：
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
  // PC1：
  // default via fd00::1:1 if 0
  RoutingTableEntry entry = {
      .addr = in6_addr{0}, .len = 0, .if_index = 0, .nexthop = default_gateway};
  update(true, entry);

  // 解析命令行参数
  // 第一个参数（argv[1]）：get 表示从服务读取文件，put 表示向服务器写入文件
  // 第二个参数（argv[2]）：服务端的 IPv6 地址
  // 第三个参数（argv[3]）：文件名
  // 例子：client get fd00::1:1 test 表示从 fd00::1:1 获取名为 test
  // 的文件到当前目录
  if (argc != 4) {
    printf("Invalid number of arguments\n");
    return 1;
  }

  if (strcmp(argv[1], "get") == 0) {
    current_transfer.is_read = true;
    current_transfer.fp = fopen(argv[3], "wb");
  } else if (strcmp(argv[1], "put") == 0) {
    current_transfer.is_read = false;
    current_transfer.fp = fopen(argv[3], "rb");
  } else {
    printf("Unsupported operation\n");
    return 1;
  }

  // 解析服务端 IPv6 地址
  current_transfer.server_addr = inet6_pton(argv[2]);

  // 在 49152-65535 范围中随机生成客户端 TID
  current_transfer.client_tid = 49152 + (rand() % 16384);
  // 此时还不知道服务端实际的 TID，先设为 0
  current_transfer.server_tid = 0;
  // 设置初始状态
  current_transfer.state = Initial;
  current_transfer.last_block_number = 0;

  bool done = false;
  uint64_t last_time = 0;
  while (!done) {
    // 初始状态下，尝试向服务器发送 Read/Write Request
    if (current_transfer.state == Initial) {
      // 根据服务端 IPv6 地址查询路由表，获得下一跳 IPv6 地址
      in6_addr nexthop;
      uint32_t dest_if;
      assert(prefix_query(current_transfer.server_addr, &nexthop, &dest_if));
      ether_addr dest_mac;
      // 如果下一跳为全 0，表示的是直连路由，目的机器和本路由器可以直接访问
      if (nexthop == in6_addr{0}) {
        nexthop = current_transfer.server_addr;
      }
      if (HAL_GetNeighborMacAddress(dest_if, nexthop, &dest_mac) == 0) {
        // 找到了下一跳 MAC 地址

        // 限制发送速度，每 1s 重试一次
        if (HAL_GetTicks() - last_time > 1000) {
          uint16_t tftp_len = sizeof(ip6_hdr) + sizeof(udphdr);
          tftp_hdr *out_tftp = (tftp_hdr *) &output[tftp_len];
          if (current_transfer.is_read) {
            // opcode = 0x01(read)
            out_tftp->opcode = htons(1);
          } else {
            // opcode = 0x02(write)
            out_tftp->opcode = htons(2);
          }
          tftp_len += sizeof(uint16_t);
          // TODO（4 行） -- Done
          // 文件名字段（argv[3]）
          strcpy((char*) &output[tftp_len], argv[3]);
          size_t payload_len = strlen(argv[3]) + 1;
          tftp_len += payload_len; // NULL-terminated
          // TODO（4 行） -- Done
          // 传输模式字段，设为 octet
          strcpy((char *) &output[tftp_len], "octet");
          tftp_len += 6;
          payload_len += 6;
          //fprintf(stderr, "Sending packet whilst initializing..., tftp_len = %lu\n", payload_len);
          send_tftp_packet(output, dest_mac, payload_len, true);
          last_time = HAL_GetTicks();
        }
      }
    }

    uint64_t time = HAL_GetTicks();

    int mask = (1 << N_IFACE_ON_BOARD) - 1;
    ether_addr src_mac;
    ether_addr dst_mac;
    int if_index;
    res = HAL_ReceiveIPPacket(mask, packet, sizeof(packet), &src_mac, &dst_mac,
                              1000, &if_index);
    #pragma region PacketValidation
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
    #pragma endregion
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
        // TODO（1 行） -- Done
        // 检查 UDP 端口，判断目的 UDP 端口是否等于客户端 TID
        udphdr *udp = (udphdr *)&packet[sizeof(ip6_hdr)];
        if (ntohs(udp->uh_dport) == current_transfer.client_tid) {

          // 检查 UDP 端口，判断源 UDP 端口是否等于服务端 TID
          // 如果还不知道服务端 TID，即此时记录的服务端 TID 为 0
          if (current_transfer.server_tid == 0) {
            // 则设置服务端 TID 为源 UDP 端口
            current_transfer.server_tid = ntohs(udp->uh_sport);
            current_transfer.state = InTransfer;
          } else {
            // TODO（1 行） -- Done
            // 检查 UDP 端口，如果源 UDP 端口不等于服务端 TID 则忽略
            if (ntohs(udp->uh_sport) != current_transfer.server_tid) {
              continue;
            }
          }

          // TODO（1 行） -- Done
          // 判断 Opcode
          tftp_hdr *tftp =
              (tftp_hdr *)&packet[sizeof(ip6_hdr) + sizeof(udphdr)];
          uint16_t opcode = ntohs(tftp->opcode);
          uint16_t block_number = ntohs(tftp->block_number);
          if (opcode == 3) {
            // 如果 Opcode 是 0x03(DATA)

            // TODO（1 行） -- Done
            // 判断 Block Number 是否等于最后一次传输的 Block Number 加一
            if (block_number - current_transfer.last_block_number == 1) {
              // TODO（6 行） -- Done
              // 如果等于，则把文件内容写到文件中
              // 并更新最后一次传输的 Block Number
              //fprintf(stderr, "File packet received w/ length = %u\n",(uint32_t) ntohs(udp->uh_ulen));
              uint16_t block_size = ntohs(udp->uh_ulen) - sizeof(udphdr) - sizeof(tftp_hdr);
              uint8_t *payload = packet + sizeof(ip6_hdr) + sizeof(udphdr) + sizeof(tftp_hdr);
              size_t bytes_written = fwrite(payload, sizeof(payload[0]), block_size, current_transfer.fp);
              //fprintf(stderr, "Bytes written = %lu\n", bytes_written);
              // 如果块的大小小于 512，说明这是最后一个块，写入文件后，
              // 关闭文件，发送 ACK 后就可以退出程序
              if (block_size < 512) {
                fclose(current_transfer.fp);
                //printf("Get file done\n");
                done = true;
              }
            }

            // 发送 ACK，其 Block Number 为最后一次传输的 Block Number
            // TODO（40 行） -- Done
            tftp_hdr *out_tftp = (tftp_hdr *) &output[sizeof(ip6_hdr) + sizeof(udphdr)];
            out_tftp->opcode = htons(4);
            out_tftp->block_number = tftp->block_number;
            //fprintf(stderr, "Sending ACK..., block number = %u\n", (uint32_t) ntohs(tftp->block_number));
            send_tftp_packet(output, src_mac, 0);
           
            current_transfer.last_block_number++;

          } else if (opcode == 4) {
            // 如果 Opcode 是 0x04(ACK)
            //fprintf(stderr, "Stored last ACK = %u, received last ACK %u\n", current_transfer.last_block_number,
            //block_number);
            // TODO（1 行） -- Done
            // 判断 Block 编号
            if (current_transfer.last_block_number == block_number) {
              // 如果 Block 编号和最后一次传输的块编号相等
              // 说明最后一次传输的块已经传输完成

              // TODO（1 行） -- Done
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
                out_tftp->opcode = htons(3);
                
                //fprintf(stderr, "Sending DATA packet with number of bytes = %lu ...\n", bytes_read);
                send_tftp_packet(output, src_mac, bytes_read);
                
                // 如果读取的字节数不足 512，则进入 LastAck 状态
                if(bytes_read < 512) 
                  current_transfer.state = LastAck;
                // Setup what last sent
                memcpy(current_transfer.last_block_data, payload, bytes_read);
                current_transfer.last_block_number = block_number;
                current_transfer.last_block_size = bytes_read;
              } else if (current_transfer.state == LastAck) {
                // 收到最后一个 ACK，说明文件传输完成
                //printf("Put file done\n");
                done = true;
              }
            } else {
              // TODO（45 行） -- Done
              // 如果 Block 编号和最后一次传输的块编号不相等
              // 说明最后一次传输的块没有传输成功
              // 重新发送最后一次传输的块
              uint8_t *payload = &output[sizeof(ip6_hdr) + sizeof(udphdr) + sizeof(tftp_hdr)];
              memcpy(payload, current_transfer.last_block_data, current_transfer.last_block_size);
              // Encapsulates packet
              tftp_hdr *out_tftp = (tftp_hdr *) &output[sizeof(ip6_hdr) + sizeof(udphdr)];
              out_tftp->block_number = htons(current_transfer.last_block_number);
              out_tftp->opcode = htons(3);

              //fprintf(stderr, "Resending last unsent packet, block number = %u...\n", (uint32_t) current_transfer.last_block_number);
              send_tftp_packet(output, src_mac, current_transfer.last_block_size);
            }
          } else if (opcode == 5) {
            // 如果 Opcode 是 0x05(ERROR)
            // 输出错误信息并退出
            uint16_t error_code = ntohs(tftp->error_code);

            char error_message[1024];
            strncpy(error_message,
                    (char *)&packet[sizeof(ip6_hdr) + sizeof(udphdr) + 4],
                    sizeof(error_message));

            printf("Got error #%d: %s\n", error_code, error_message);
            done = true;
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
