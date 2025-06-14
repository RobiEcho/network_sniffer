#include "packet_parser.h"
#include <stdlib.h>
#include <string.h>
#include <ifaddrs.h>
#include <errno.h>

/**
 * @brief 创建一个数据包上下文结构体，并复制数据内容
 * 
 * 此函数分配内存并复制数据包内容，初始化PacketContext结构体
 */
PacketContext* create_packet_context(const uint8_t *data, size_t length) {
    if (!data || length == 0) {
        fprintf(stderr, "创建数据包上下文失败: 无效的参数\n");
        return NULL;
    }
    
    PacketContext *context = (PacketContext*)malloc(sizeof(PacketContext));
    if (!context) {
        fprintf(stderr, "创建数据包上下文失败: 内存分配错误 (errno: %d)\n", errno);
        return NULL;
    }
    
    // 分配内存并复制数据包内容
    uint8_t *data_copy = (uint8_t*)malloc(length);
    if (!data_copy) {
        fprintf(stderr, "创建数据包上下文失败: 内存分配错误 (errno: %d)\n", errno);
        free(context);
        return NULL;
    }
    
    // 初始化原始数据
    memcpy(data_copy, data, length);
    context->raw_data.data = data_copy;
    context->raw_data.length = length;
    
    // 初始化网络信息
    context->network_info.src_ip[0] = '\0';
    context->network_info.dst_ip[0] = '\0';
    context->network_info.total_size = 0;
    context->network_info.protocol = 0;
    
    // 初始化状态标志位
    context->parse_status.status.flags = 0; // 所有标志位清零
    
    // 初始化协议头部指针
    context->protocol_headers.eth_header = NULL;
    context->protocol_headers.ip_header = NULL;
    context->protocol_headers.tcp_header = NULL;
    context->protocol_headers.udp_header = NULL;
    
    return context;
}

/**
 * @brief 释放数据包上下文结构体及其内部数据
 */
void free_packet_context(PacketContext *context) {
    if (!context) {
        return;
    }
    
    if (context->raw_data.data) {
        free((void*)context->raw_data.data); // 释放数据内容
    }
    
    free(context); // 释放结构体本身
}

/**
 * @brief 以太网帧解码器
 * 
 * 解析以太网帧头部
 */
int decode_ethernet(PacketContext *context) {
    if (!context || !context->raw_data.data || context->raw_data.length < sizeof(MyEthHeader)) {
        fprintf(stderr, "以太网帧解码失败: 无效的数据包或长度不足\n");
        return -1;
    }
    
    // 设置以太网头部指针
    context->protocol_headers.eth_header = (const MyEthHeader*)context->raw_data.data;
    
    // 更新解析状态
    context->parse_status.status.bits.eth_layer_parsed = 1;
    
    return 0;
}

/**
 * @brief IP包解码器
 * 
 * 解析IP包头部，提取源IP、目的IP和协议类型
 */
int decode_ip(PacketContext *context) {
    if (!context || !context->protocol_headers.eth_header) {
        fprintf(stderr, "IP包解码失败: 无效的数据包或未解析以太网头\n");
        return -1;
    }
    
    // 确保数据包长度足够包含IP头部
    size_t eth_header_size = sizeof(MyEthHeader);
    if (context->raw_data.length < eth_header_size + sizeof(MyIpHeader)) {
        fprintf(stderr, "IP包解码失败: 数据包长度不足\n");
        return -1;
    }
    
    // 设置IP头部指针
    context->protocol_headers.ip_header = (const MyIpHeader*)(context->raw_data.data + eth_header_size);
    
    // 提取源IP和目的IP地址
    if (inet_ntop(AF_INET, &(context->protocol_headers.ip_header->src_addr), 
                  context->network_info.src_ip, INET_ADDRSTRLEN) == NULL) {
        fprintf(stderr, "IP包解码失败: 无法转换源IP地址 (errno: %d)\n", errno);
        return -1;
    }
    
    if (inet_ntop(AF_INET, &(context->protocol_headers.ip_header->dst_addr), 
                  context->network_info.dst_ip, INET_ADDRSTRLEN) == NULL) {
        fprintf(stderr, "IP包解码失败: 无法转换目的IP地址 (errno: %d)\n", errno);
        return -1;
    }
    
    // 提取数据包总长度和协议类型
    context->network_info.total_size = ntohs(context->protocol_headers.ip_header->total_length);
    context->network_info.protocol = context->protocol_headers.ip_header->protocol;
    
    // 更新解析状态
    context->parse_status.status.bits.ip_layer_parsed = 1;
    
    return 0;
}

/**
 * @brief TCP段解码器
 * 
 * 解析TCP段
 */
int decode_tcp(PacketContext *context) {
    if (!context || !context->protocol_headers.ip_header) {
        fprintf(stderr, "TCP解码失败: 无效的数据包或未解析IP头\n");
        return -1;
    }
    
    // 计算IP头部长度
    size_t ip_header_size = context->protocol_headers.ip_header->ihl * 4;
    size_t eth_header_size = sizeof(MyEthHeader);
    size_t tcp_offset = eth_header_size + ip_header_size;
    
    // 确保数据包长度足够包含TCP头部
    if (context->raw_data.length < tcp_offset + sizeof(MyTcpHeader)) {
        fprintf(stderr, "TCP解码失败: 数据包长度不足\n");
        return -1;
    }
    
    // 设置TCP头部指针
    context->protocol_headers.tcp_header = (const MyTcpHeader*)(context->raw_data.data + tcp_offset);
    
    // TCP解码成功，设置解析标志位
    context->parse_status.status.bits.is_parsed = 1;
    context->parse_status.status.bits.tcp_layer_parsed = 1;
    
    return 0;
}

/**
 * @brief UDP段解码器
 * 
 * 解析UDP段
 */
int decode_udp(PacketContext *context) {
    if (!context || !context->protocol_headers.ip_header) {
        fprintf(stderr, "UDP解码失败: 无效的数据包或未解析IP头\n");
        return -1;
    }
    
    // 计算IP头部长度
    size_t ip_header_size = context->protocol_headers.ip_header->ihl * 4;
    size_t eth_header_size = sizeof(MyEthHeader);
    size_t udp_offset = eth_header_size + ip_header_size;
    
    // 确保数据包长度足够包含UDP头部
    if (context->raw_data.length < udp_offset + sizeof(MyUdpHeader)) {
        fprintf(stderr, "UDP解码失败: 数据包长度不足\n");
        return -1;
    }
    
    // 设置UDP头部指针
    context->protocol_headers.udp_header = (const MyUdpHeader*)(context->raw_data.data + udp_offset);
    
    // UDP解码成功，设置解析标志位
    context->parse_status.status.bits.is_parsed = 1;
    context->parse_status.status.bits.udp_layer_parsed = 1;
    
    return 0;
}

/**
 * @brief 获取本机IP地址
 * 
 * 此函数遍历所有网络接口，查找第一个非回环的IPv4地址
 */
int get_local_ip(char *local_ip, size_t size) {
    if (!local_ip || size < INET_ADDRSTRLEN) {
        fprintf(stderr, "获取本机IP失败: 无效的缓冲区\n");
        return -1;
    }
    
    struct ifaddrs *ifaddr, *ifa;
    int family, s;

    if (getifaddrs(&ifaddr) == -1) {
        fprintf(stderr, "获取本机IP失败: 无法获取网络接口列表 (errno: %d)\n", errno);
        return -1;
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
            return 0;
        }
    }

    fprintf(stderr, "获取本机IP失败: 未找到有效的非回环IPv4地址\n");
    freeifaddrs(ifaddr);
    return -1;
}