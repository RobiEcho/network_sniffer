#ifndef PACKET_PARSER_H
#define PACKET_PARSER_H

#include <pcap.h>

#define ETH_ALEN 6

// 以太网协议类型定义
#define ETH_P_IP    0x0800  // IPv4协议
#define ETH_P_ARP   0x0806  // ARP协议
#define ETH_P_IPV6  0x86DD  // IPv6协议
#define ETH_P_8021Q 0x8100  // 802.1Q VLAN标签

// 以太网头部结构
typedef struct {
    uint8_t dest_mac[ETH_ALEN];  // 目标MAC地址
    uint8_t src_mac[ETH_ALEN];   // 源MAC地址
    uint16_t ether_type;         // 以太网类型
} MyEthHeader;

// IP头部结构
typedef struct __attribute__((packed)) {
    uint8_t version:4;       // 版本
    uint8_t ihl:4;           // 头部长度（以4字节为单位）
    uint8_t tos;             // 服务类型
    uint16_t total_length;   // 总长度
    uint16_t id;             // 标识
    uint16_t flags_offset;   // 标志+片偏移
    uint8_t ttl;             // 生存时间
    uint8_t protocol;        // 协议
    uint16_t checksum;       // 头部校验和
    struct in_addr src_addr; // 源IP地址
    struct in_addr dst_addr; // 目的IP地址
} MyIpHeader;

// TCP 头 
typedef struct {
    unsigned short sport;    // 源端口号
    unsigned short dport;    // 目的端口号
    unsigned int seq;        // 序列号
    unsigned int ack_seq;    // 确认号
    unsigned char len;       // 头部长度
    unsigned char flag;      // 控制标志
    unsigned short win;      // 窗口大小
    unsigned short checksum; // 校验和
    unsigned short urg;      // 紧急指针
} MyTcpHeader;

// UDP 头
typedef struct {
    u_int16_t sport; // 源端口
    u_int16_t dport; // 目的端口
    u_int16_t ulen;  // UDP数据报长度
    u_int16_t sum;   // UDP校验和
} MyUdpHeader;

/**
 * @brief 增强的数据包信息结构，包含原始数据和解析后的信息
 */
typedef struct {
    const uint8_t *data;               // 原始数据包内容
    size_t length;                     // 数据包长度
    char src_ip[INET_ADDRSTRLEN];      // 源IP地址 (解析后)
    char dst_ip[INET_ADDRSTRLEN];      // 目的IP地址 (解析后)
    int total_size;                    // 数据包总大小 (字节)
    int is_parsed;                     // 是否已经解析
    int protocol;                      // IP协议类型 (TCP/UDP等)
    const MyEthHeader *eth_header;     // 以太网头部指针
    const MyIpHeader *ip_header;       // IP头部指针
    const MyTcpHeader *tcp_header;     // TCP头部指针（如果是TCP）
    const MyUdpHeader *udp_header;     // UDP头部指针（如果是UDP）
} PacketInfo;

/**
 * @brief 创建一个数据包信息结构体，并复制数据内容
 * @param data   指向原始数据包内容的指针
 * @param length 数据包内容的长度（字节数）
 * @return PacketInfo* 指向新分配并初始化的 PacketInfo 结构体指针，需用 free_packet_info 释放
 * @note 初始化后的结构体中is_parsed为0，表示尚未解析
 */
PacketInfo* create_packet_info(const uint8_t *data, size_t length);

/**
 * @brief 释放由 create_packet_info 创建的数据包信息结构体及其内部数据。
 * @param info 需要释放的 PacketInfo 结构体指针
 */
void free_packet_info(PacketInfo *info);

/**
 * @brief 解析数据包，提取源IP、目的IP和数据包大小
 * @param info 指向待解析的数据包信息结构体
 * @return int 成功返回1，失败返回0
 * @note 解析结果直接存储在info结构体中，成功解析后is_parsed设为1
 */
int parse_packet(PacketInfo *info);

/**
 * @brief 获取本机IP地址
 * @param local_ip 存储本机IP的缓冲区
 * @param size 缓冲区大小，应至少为INET_ADDRSTRLEN
 * @return int 成功返回1，失败返回0
 * @note 此函数会尝试获取第一个非回环(非127.0.0.1)的IPv4地址
 */
int get_local_ip(char *local_ip, size_t size);

/**
 * @brief 以太网帧解码器
 * @param info 数据包信息
 * @return int 成功返回1，失败返回0
 */
int decode_ethernet(PacketInfo *info);

/**
 * @brief IP包解码器
 * @param info 数据包信息
 * @return int 成功返回1，失败返回0
 */
int decode_ip(PacketInfo *info);

/**
 * @brief TCP段解码器
 * @param info 数据包信息
 * @return int 成功返回1，失败返回0
 */
int decode_tcp(PacketInfo *info);

/**
 * @brief UDP段解码器
 * @param info 数据包信息
 * @return int 成功返回1，失败返回0
 */
int decode_udp(PacketInfo *info);

#endif // PACKET_PARSER_H