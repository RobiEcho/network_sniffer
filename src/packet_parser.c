#include "packet_parser.h"
#include <stdlib.h>
#include <string.h>
#include <ifaddrs.h>

// 创建一个数据包信息结构体，并复制数据内容
PacketInfo* create_packet_info(const uint8_t *data, size_t length) {
    PacketInfo *info = (PacketInfo*)malloc(sizeof(PacketInfo));
    if (!info) return NULL;
    
    // 分配内存并复制数据包内容
    uint8_t *data_copy = (uint8_t*)malloc(length);
    if (!data_copy) {
        free(info);
        return NULL;
    }
    
    memcpy(data_copy, data, length);
    info->data = data_copy;
    info->length = length;
    return info;
}

void free_packet_info(PacketInfo *info) {
    if (info) {
        if (info->data) free((void*)info->data); // 释放数据内容
        free(info); // 释放结构体本身
    }
}

// 解析数据包，提取源IP、目的IP和数据包大小
Packetdelivery* parse_packet(PacketInfo *info) {
    if (!info) {
        return NULL;
    }
    
    // 解析以太网头部
    const MyEthHeader *eth_header = (const MyEthHeader*)info->data;

    if (ntohs(eth_header->ether_type) == 0x0800 ) {
        // 解析IP头部
        const MyIpHeader *ip_header = (const MyIpHeader*)(info->data + sizeof(MyEthHeader));
        
        Packetdelivery* data = malloc(sizeof(Packetdelivery));
        if (!data) {
            return NULL;
        }
        // 提取源IP和目的IP地址，以及数据包大小
        inet_ntop(AF_INET, &(ip_header->src_addr), data->src_ip, INET_ADDRSTRLEN);
        inet_ntop(AF_INET, &(ip_header->dst_addr), data->dst_ip, INET_ADDRSTRLEN);
        data->total_size = ntohs(ip_header->total_length);
        /*
        // 对上层协议处理
        switch (ip_header->protocol)
        {
        case IPPROTO_TCP:
            printf("Protocol: TCP\n");
            // 获取tcp报头
            MyTcpHeader *tcp = (MyTcpHeader *)(info->data + sizeof(MyEthHeader) + sizeof(MyIpHeader));
            // 输出源和目的端口号
            printf("From: %d\n", ntohs(tcp->sport));
            printf("To: %d\n", ntohs(tcp->dport));
            // 输出协议的payload
            return NULL;
        case IPPROTO_UDP:
            printf("Protocol: UDP\n");
            // 获取udp报头
            MyUdpHeader *udp = (MyUdpHeader *)(info->data + sizeof(MyEthHeader) + sizeof(MyIpHeader));
            // 输出源和目的端口号
            printf("From: %d\n", ntohs(udp->sport));
            printf("To: %d\n", ntohs(udp->dport));
            // 输出协议的payload
            return NULL;
        case IPPROTO_ICMP:
            printf("Protocol: ICMP\n");
            return NULL;
        default:
            printf("Protocol: others\n");
            return NULL;
        }
        */
        return data;
    }
    else if (ntohs(eth_header->ether_type) == 0x0806)
    {
        printf("Protocol: ARP\n");
        return NULL;
    }
    else if (ntohs(eth_header->ether_type) == 0x86DD)
    {
        printf("Protocol: IPv6\n");
        return NULL;
    } else {
        printf("Protocol: others\n");
        return NULL;
    }
}

void free_packet_delivery(Packetdelivery *data)
{
    if (data != NULL)
    {
        free(data);
    }
}

// 获取本机IP地址
int get_local_ip(char *local_ip, size_t size) {
    struct ifaddrs *ifaddr, *ifa;
    int family, s;

    if (getifaddrs(&ifaddr) == -1) {
        return 0;
    }

    // 遍历所有网络接口
    for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr == NULL) continue;

        family = ifa->ifa_addr->sa_family;

        // 只处理IPv4地址
        if (family == AF_INET) {
            s = getnameinfo(ifa->ifa_addr, sizeof(struct sockaddr_in),
                    local_ip, size, NULL, 0, NI_NUMERICHOST);
            if (s != 0) continue;

            // 跳过回环接口
            if (strcmp(local_ip, "127.0.0.1") == 0) continue;

            // 找到一个有效的非回环IPv4地址
            freeifaddrs(ifaddr);
            return 1;
        }
    }

    freeifaddrs(ifaddr);
    return 0;
}