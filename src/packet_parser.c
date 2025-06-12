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
 * @brief 解析数据包，提取源IP、目的IP和数据包大小
 * 
 * 此函数解析以太网和IP头部，提取源IP和目的IP，以及数据包大小
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
    
    // 确保数据包长度足够包含以太网和IP头部
    if (info->length < sizeof(MyEthHeader) + sizeof(MyIpHeader)) {
        fprintf(stderr, "解析数据包失败: 数据包长度不足\n");
        return 0;
    }
    
    // 解析以太网头部
    const MyEthHeader *eth_header = (const MyEthHeader*)info->data;
    uint16_t ether_type = ntohs(eth_header->ether_type);
    
    // 只处理IPv4数据包
    if (ether_type == 0x0800) {
        // 解析IP头部
        const MyIpHeader *ip_header = (const MyIpHeader*)(info->data + sizeof(MyEthHeader));
        
        // 提取源IP和目的IP地址，以及数据包大小
        if (inet_ntop(AF_INET, &(ip_header->src_addr), info->src_ip, INET_ADDRSTRLEN) == NULL) {
            fprintf(stderr, "解析数据包失败: 无法转换源IP地址 (errno: %d)\n", errno);
            return 0;
        }
        
        if (inet_ntop(AF_INET, &(ip_header->dst_addr), info->dst_ip, INET_ADDRSTRLEN) == NULL) {
            fprintf(stderr, "解析数据包失败: 无法转换目的IP地址 (errno: %d)\n", errno);
            return 0;
        }
        
        info->total_size = ntohs(ip_header->total_length);
        info->is_parsed = 1; // 标记为已解析
        
        return 1; // 解析成功
    }
    else if (ether_type == 0x0806) {
        fprintf(stderr, "不支持的协议: ARP\n");
    }
    else if (ether_type == 0x86DD) {
        fprintf(stderr, "不支持的协议: IPv6\n");
    } 
    else {
        fprintf(stderr, "不支持的协议: 0x%04x\n", ether_type);
    }
    
    return 0; // 不支持的协议
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