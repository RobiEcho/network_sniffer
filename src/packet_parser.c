#include "packet_parser.h"
#include <stdlib.h>
#include <string.h>
#include <ifaddrs.h>
#include <errno.h>

/**
 * @brief 创建一个数据包信息结构体，并复制数据内容
 * 
 * 此函数分配内存并复制数据包内容，初始化PacketInfo结构体
 */
PacketInfo* create_packet_info(const uint8_t *data, size_t length) {
    if (!data || length == 0) {
        fprintf(stderr, "创建数据包信息失败: 无效的参数\n");
        return NULL;
    }
    
    PacketInfo *info = (PacketInfo*)malloc(sizeof(PacketInfo));
    if (!info) {
        fprintf(stderr, "创建数据包信息失败: 内存分配错误 (errno: %d)\n", errno);
        return NULL;
    }
    
    // 分配内存并复制数据包内容
    uint8_t *data_copy = (uint8_t*)malloc(length);
    if (!data_copy) {
        fprintf(stderr, "创建数据包信息失败: 内存分配错误 (errno: %d)\n", errno);
        free(info);
        return NULL;
    }
    
    // 初始化结构体字段
    memcpy(data_copy, data, length);
    info->data = data_copy;
    info->length = length;
    info->src_ip[0] = '\0';
    info->dst_ip[0] = '\0';
    info->total_size = 0;
    info->is_parsed = 0;
    info->protocol = 0;
    info->eth_header = NULL;
    info->ip_header = NULL;
    info->tcp_header = NULL;
    info->udp_header = NULL;
    
    return info;
}

/**
 * @brief 释放数据包信息结构体及其内部数据
 */
void free_packet_info(PacketInfo *info) {
    if (!info) {
        return;
    }
    
    if (info->data) {
        free((void*)info->data); // 释放数据内容
    }
    
    free(info); // 释放结构体本身
}

/**
 * @brief 以太网帧解码器
 * 
 * 解析以太网帧头部，并根据协议类型决定下一步解析
 */
int decode_ethernet(PacketInfo *info) {
    if (!info || !info->data || info->length < sizeof(MyEthHeader)) {
        fprintf(stderr, "以太网帧解码失败: 无效的数据包或长度不足\n");
        return 0;
    }
    
    // 设置以太网头部指针
    info->eth_header = (const MyEthHeader*)info->data;
    
    // 获取以太网类型
    uint16_t ether_type = ntohs(info->eth_header->ether_type);
    
    // 根据以太网类型进行后续处理
    switch (ether_type) {
        case ETH_P_IP:
            // 继续解析IP协议
            return decode_ip(info);
            
        case ETH_P_ARP:
            fprintf(stderr, "以太网帧类型: ARP 协议（暂不支持）\n");
            return 0;
            
        case ETH_P_IPV6:
            fprintf(stderr, "以太网帧类型: IPv6 协议（暂不支持）\n");
            return 0;
            
        default:
            fprintf(stderr, "以太网帧类型: 0x%04x（暂不支持）\n", ether_type);
            return 0;
    }
}

/**
 * @brief IP包解码器
 * 
 * 解析IP包头部，提取源IP、目的IP和协议类型
 */
int decode_ip(PacketInfo *info) {
    if (!info || !info->eth_header) {
        fprintf(stderr, "IP包解码失败: 无效的数据包或未解析以太网头\n");
        return 0;
    }
    
    // 确保数据包长度足够包含IP头部
    size_t eth_header_size = sizeof(MyEthHeader);
    if (info->length < eth_header_size + sizeof(MyIpHeader)) {
        fprintf(stderr, "IP包解码失败: 数据包长度不足\n");
        return 0;
    }
    
    // 设置IP头部指针
    info->ip_header = (const MyIpHeader*)(info->data + eth_header_size);
    
    // 提取源IP和目的IP地址
    if (inet_ntop(AF_INET, &(info->ip_header->src_addr), info->src_ip, INET_ADDRSTRLEN) == NULL) {
        fprintf(stderr, "IP包解码失败: 无法转换源IP地址 (errno: %d)\n", errno);
        return 0;
    }
    
    if (inet_ntop(AF_INET, &(info->ip_header->dst_addr), info->dst_ip, INET_ADDRSTRLEN) == NULL) {
        fprintf(stderr, "IP包解码失败: 无法转换目的IP地址 (errno: %d)\n", errno);
        return 0;
    }
    
    // 提取数据包总长度和协议类型
    info->total_size = ntohs(info->ip_header->total_length);
    info->protocol = info->ip_header->protocol;
    
    // 根据IP协议类型进行后续处理
    switch (info->protocol) {
        case IPPROTO_TCP:
            // 预留TCP解码器接口
            return decode_tcp(info);
            
        case IPPROTO_UDP:
            // 预留UDP解码器接口
            return decode_udp(info);
            
        case IPPROTO_ICMP:
            fprintf(stderr, "IP协议类型: ICMP 协议（暂不支持详细解析）\n");
            // 虽然不解析ICMP协议详情，但IP解析已成功
            info->is_parsed = 1;
            return 1;
            
        default:
            fprintf(stderr, "IP协议类型: %d（暂不支持详细解析）\n", info->protocol);
            // 虽然不解析其他协议详情，但IP解析已成功
            info->is_parsed = 1;
            return 1;
    }
}

/**
 * @brief TCP段解码器
 * 
 * 预留接口，目前仅标记数据包已解析
 */
int decode_tcp(PacketInfo *info) {
    if (!info || !info->ip_header) {
        fprintf(stderr, "TCP解码失败: 无效的数据包或未解析IP头\n");
        return 0;
    }
    
    // 计算IP头部长度
    size_t ip_header_size = info->ip_header->ihl * 4;
    size_t eth_header_size = sizeof(MyEthHeader);
    size_t tcp_offset = eth_header_size + ip_header_size;
    
    // 确保数据包长度足够包含TCP头部
    if (info->length < tcp_offset + sizeof(MyTcpHeader)) {
        fprintf(stderr, "TCP解码失败: 数据包长度不足\n");
        return 0;
    }
    
    // 设置TCP头部指针
    info->tcp_header = (const MyTcpHeader*)(info->data + tcp_offset);
    
    // TCP解码成功
    info->is_parsed = 1;
    return 1;
}

/**
 * @brief UDP段解码器
 * 
 * 预留接口，目前仅标记数据包已解析
 */
int decode_udp(PacketInfo *info) {
    if (!info || !info->ip_header) {
        fprintf(stderr, "UDP解码失败: 无效的数据包或未解析IP头\n");
        return 0;
    }
    
    // 计算IP头部长度
    size_t ip_header_size = info->ip_header->ihl * 4;
    size_t eth_header_size = sizeof(MyEthHeader);
    size_t udp_offset = eth_header_size + ip_header_size;
    
    // 确保数据包长度足够包含UDP头部
    if (info->length < udp_offset + sizeof(MyUdpHeader)) {
        fprintf(stderr, "UDP解码失败: 数据包长度不足\n");
        return 0;
    }
    
    // 设置UDP头部指针
    info->udp_header = (const MyUdpHeader*)(info->data + udp_offset);
    
    // UDP解码成功
    info->is_parsed = 1;
    return 1;
}

/**
 * @brief 解析数据包，提取源IP、目的IP和数据包大小
 * 
 * 此函数使用责任链模式解析数据包，从以太网层开始
 */
int parse_packet(PacketInfo *info) {
    if (!info || !info->data) {
        fprintf(stderr, "解析数据包失败: 无效的数据包信息\n");
        return 0;
    }
    
    // 如果已经解析过，直接返回成功
    if (info->is_parsed) {
        return 1;
    }
    
    // 使用以太网解码器开始解析
    return decode_ethernet(info);
}

/**
 * @brief 获取本机IP地址
 * 
 * 此函数遍历所有网络接口，查找第一个非回环的IPv4地址
 */
int get_local_ip(char *local_ip, size_t size) {
    if (!local_ip || size < INET_ADDRSTRLEN) {
        fprintf(stderr, "获取本机IP失败: 无效的缓冲区\n");
        return 0;
    }
    
    struct ifaddrs *ifaddr, *ifa;
    int family, s;

    if (getifaddrs(&ifaddr) == -1) {
        fprintf(stderr, "获取本机IP失败: 无法获取网络接口列表 (errno: %d)\n", errno);
        return 0;
    }

    // 遍历所有网络接口
    for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr == NULL) {
            continue;
        }

        family = ifa->ifa_addr->sa_family;

        // 只处理IPv4地址
        if (family == AF_INET) {
            s = getnameinfo(ifa->ifa_addr, sizeof(struct sockaddr_in),
                    local_ip, size, NULL, 0, NI_NUMERICHOST);
            if (s != 0) {
                fprintf(stderr, "获取本机IP失败: getnameinfo错误: %s\n", gai_strerror(s));
                continue;
            }

            // 跳过回环接口
            if (strcmp(local_ip, "127.0.0.1") == 0) {
                continue;
            }

            // 找到一个有效的非回环IPv4地址
            freeifaddrs(ifaddr);
            return 1;
        }
    }

    fprintf(stderr, "获取本机IP失败: 未找到有效的非回环IPv4地址\n");
    freeifaddrs(ifaddr);
    return 0;
}