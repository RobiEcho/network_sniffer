#ifndef PACKET_PARSER_H
#define PACKET_PARSER_H

#include <pcap.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <stdio.h>

#define ETH_ALEN 6

// 以太网协议类型定义
#define ETH_P_IP    0x0800  // IPv4协议
#define ETH_P_ARP   0x0806  // ARP协议
#define ETH_P_IPV6  0x86DD  // IPv6协议
#define ETH_P_8021Q 0x8100  // 802.1Q VLAN标签

// 数据包状态标志位定义
#define PKT_FLAG_PARSED       0x01  // 是否已解析
#define PKT_FLAG_ETH_PARSED   0x02  // 以太网层是否已解析
#define PKT_FLAG_IP_PARSED    0x04  // IP层是否已解析
#define PKT_FLAG_TCP_PARSED   0x08  // TCP层是否已解析
#define PKT_FLAG_UDP_PARSED   0x10  // UDP层是否已解析

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
 * @brief 原始数据包数据结构，负责存储原始数据
 */
typedef struct {
    const uint8_t *data;     // 原始数据包内容
    size_t length;           // 数据包长度
} RawPacketData;

/**
 * @brief 数据包解析状态结构，负责跟踪解析进度
 */
typedef struct {
    union {
        uint8_t flags;                 // 所有标志位
        struct {
            uint8_t is_parsed : 1;     // 是否已经完全解析
            uint8_t eth_layer_parsed : 1; // 以太网层是否已解析
            uint8_t ip_layer_parsed : 1;  // IP层是否已解析
            uint8_t tcp_layer_parsed : 1; // TCP层是否已解析
            uint8_t udp_layer_parsed : 1; // UDP层是否已解析
            uint8_t reserved : 3;      // 保留位
        } bits;
    } status;
} PacketParseStatus;

/**
 * @brief 协议头部指针结构，负责存储各层协议的头部指针
 */
typedef struct {
    const MyEthHeader *eth_header;     // 以太网头部指针
    const MyIpHeader *ip_header;       // IP头部指针
    const MyTcpHeader *tcp_header;     // TCP头部指针（如果是TCP）
    const MyUdpHeader *udp_header;     // UDP头部指针（如果是UDP）
} ProtocolHeaders;

/**
 * @brief 网络信息结构，负责存储解析后的网络信息
 */
typedef struct {
    char src_ip[INET_ADDRSTRLEN];      // 源IP地址 (解析后)
    char dst_ip[INET_ADDRSTRLEN];      // 目的IP地址 (解析后)
    int total_size;                    // 流量总大小 (字节)
    int protocol;                      // IP协议类型 (TCP/UDP等)
} NetworkInfo;

/**
 * @brief 数据包上下文结构，整合所有组件
 */
typedef struct {
    RawPacketData raw_data;              // 原始数据包数据
    PacketParseStatus parse_status;      // 解析状态
    ProtocolHeaders protocol_headers;    // 协议头部指针
    NetworkInfo network_info;            // 网络信息
} PacketContext;

/**
 * @brief 创建一个数据包上下文结构体，并复制数据内容
 * @param data   指向原始数据包内容的指针
 * @param length 数据包内容的长度（字节数）
 * @return 返回新分配并初始化的 PacketContext 结构体指针，需用 free_packet_context 释放
 */
PacketContext* create_packet_context(const uint8_t *data, size_t length);

/**
 * @brief 释放由 create_packet_context 创建的数据包上下文结构体及其内部数据
 * @param context 需要释放的 PacketContext 结构体指针
 */
void free_packet_context(PacketContext *context);

/**
 * @brief 以太网帧解码器
 * @param context 数据包上下文
 * @return int 成功返回0，失败返回-1
 * @note 成功时会设置 eth_header 指针并更新状态标志位
 */
int decode_ethernet(PacketContext *context);

/**
 * @brief IP包解码器
 * @param context 数据包上下文
 * @return int 成功返回0，失败返回-1
 * @note 成功时会设置 ip_header 指针、网络信息，并更新状态标志位
 */
int decode_ip(PacketContext *context);

/**
 * @brief TCP段解码器
 * @param context 数据包上下文
 * @return int 成功返回0，失败返回-1
 * @note 成功时会设置 tcp_header 指针并更新状态标志位
 */
int decode_tcp(PacketContext *context);

/**
 * @brief UDP段解码器
 * @param context 数据包上下文
 * @return int 成功返回0，失败返回-1
 * @note 成功时会设置 udp_header 指针并更新状态标志位
 */
int decode_udp(PacketContext *context);

/**
 * @brief 获取本机IP地址
 * @param local_ip 存储本机IP的缓冲区
 * @param size 缓冲区大小，应至少为INET_ADDRSTRLEN
 * @return int 成功返回0，失败返回-1
 * @note 此函数会尝试获取第一个非回环(非127.0.0.1)的IPv4地址
 */
int get_local_ip(char *local_ip, size_t size);

#endif // PACKET_PARSER_H