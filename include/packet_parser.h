#ifndef PACKET_PARSER_H
#define PACKET_PARSER_H

#include <pcap.h>

#define ETH_ALEN 6

// 以太网头部结构
typedef struct {
    uint8_t dest_mac[ETH_ALEN];
    uint8_t src_mac[ETH_ALEN];
    uint16_t ether_type;
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

/* TCP 头 */
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

/* UDP Header */
typedef struct {
    u_int16_t sport; /* 源端口 */
    u_int16_t dport; /* 目的端口 */
    u_int16_t ulen;  /* UDP数据报长度 */
    u_int16_t sum;   /* UDP校验和 */
} MyUdpHeader;

// 数据包信息结构
typedef struct {
    const uint8_t *data;
    size_t length;
} PacketInfo;

// 解析得到的源ip和目的ip，以及流量大小
typedef struct {
    char src_ip[INET_ADDRSTRLEN];
    char dst_ip[INET_ADDRSTRLEN];
    int total_size;
} Packetdelivery;

/**
 * @brief 创建一个数据包信息结构体，并复制数据内容
 * @param data   指向原始数据包内容的指针
 * @param length 数据包内容的长度（字节数）
 * @return PacketInfo* 指向新分配并初始化的 PacketInfo 结构体指针，需用 free_packet_info 释放
 */
PacketInfo* create_packet_info(const uint8_t *data, size_t length);

/**
 * @brief 释放由 create_packet_info 创建的数据包信息结构体及其内部数据。
 * @param info 需要释放的 PacketInfo 结构体指针
 */
void free_packet_info(PacketInfo *info);

/**
 * @brief 解析并记录数据包传递参数
 * @param info 指向待解析的数据包信息结构体
 * @return Packetdelivery* 指向新分配并初始化的 Packetdelivery 结构体指针  
 */
Packetdelivery* parse_packet(PacketInfo *info);

/**
 * @brief 释放解析数据包得到的参数结构体
 * @param data 需要释放的 Packetdelivery 结构体指针
 */
void free_packet_delivery(Packetdelivery *data);

/**
 * @brief 获取本机IP地址
 * @param local_ip 存储本机IP的缓冲区
 * @param size 缓冲区大小
 * @return int 成功返回1，失败返回0
 */
int get_local_ip(char *local_ip, size_t size);

#endif // PACKET_PARSER_H