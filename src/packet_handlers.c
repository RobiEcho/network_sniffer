#include "packet_handlers.h"
#include "traffic_analyzer.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>

// 外部全局变量（定义在main.c中）
extern TrafficAnalyzer *traffic_analyzer; // 流量分析器
extern pthread_mutex_t analyzer_mutex;    // 互斥锁

// 过滤处理器上下文
typedef struct {
    char filter_ip[INET_ADDRSTRLEN];  // 过滤的IP地址
    int filter_type;                  // 过滤类型：1-源IP，2-目的IP
} filter_context_t;

/**
 * @brief 空处理函数
 * 
 * 用于预留节点，不做任何操作，仅返回0表示处理成功
 */
int dummy_handler(void *req, void *ctx) {
    return 0; // 不做任何操作，直接返回成功
}

/**
 * @brief 创建数据包请求
 * 
 * 分配内存并初始化请求结构体的各个字段
 */
packet_request_t *create_packet_request(PacketInfo *packet_info, const char *local_ip) {
    if (!packet_info || !local_ip) {
        fprintf(stderr, "创建数据包请求失败: 无效的参数\n");
        return NULL;
    }
    
    // 分配请求结构体内存
    packet_request_t *request = (packet_request_t *)malloc(sizeof(packet_request_t));
    if (!request) {
        fprintf(stderr, "创建数据包请求失败: 内存分配错误 (errno: %d)\n", errno);
        return NULL;
    }
    
    // 初始化请求结构体字段
    request->packet_info = packet_info;
    
    // 复制本地IP地址（确保正确终止字符串）
    if (strlen(local_ip) >= INET_ADDRSTRLEN) {
        fprintf(stderr, "创建数据包请求失败: 本地IP地址过长\n");
        free(request);
        return NULL;
    }
    
    strncpy(request->local_ip, local_ip, INET_ADDRSTRLEN - 1);
    request->local_ip[INET_ADDRSTRLEN - 1] = '\0';
    
    request->handler_type = 0;  // 初始化处理类型为0
    request->extra_data = NULL; // 初始化额外数据为NULL
    
    return request;
}

/**
 * @brief 释放数据包请求
 * 
 * 释放请求结构体，但不释放packet_info（由调用者负责）
 */
void free_packet_request(packet_request_t *request) {
    if (!request) {
        return;
    }
    
    // 注意：不释放packet_info，由调用者负责
    free(request);
}

/**
 * @brief 以太网解码处理器 - 处理以太网帧
 * 
 * 责任链中的第一个处理器，负责解析以太网帧
 */
int eth_decode_handler(void *req, void *ctx) {
    packet_request_t *request = (packet_request_t *)req;
    if (!request || !request->packet_info) {
        fprintf(stderr, "以太网解码处理器: 无效的请求\n");
        return -1;
    }
    
    // 设置当前处理类型
    request->handler_type = HANDLER_TYPE_ETH_DECODE;
    
    // 解析以太网帧
    if (!decode_ethernet(request->packet_info)) {
        fprintf(stderr, "以太网解码处理器: 解析以太网帧失败\n");
        return -1;
    }
    
    return 0; // 解析成功
}

/**
 * @brief IP解码处理器 - 处理IP数据包
 * 
 * 作为以太网解码处理器的子处理器，负责解析IP数据包
 */
int ip_decode_handler(void *req, void *ctx) {
    packet_request_t *request = (packet_request_t *)req;
    
    if (!request || !request->packet_info || !request->packet_info->eth_header) {
        fprintf(stderr, "IP解码处理器: 无效的请求或未解析以太网头\n");
        return -1;
    }
    
    // 确认以太网类型是IP
    uint16_t ether_type = ntohs(request->packet_info->eth_header->ether_type);
    if (ether_type != ETH_P_IP) {
        fprintf(stderr, "IP解码处理器: 不是IP数据包，跳过\n");
        return -1; // 非IP协议，但允许其他处理器继续
    }
    
    // 设置当前处理类型
    request->handler_type = HANDLER_TYPE_IP_DECODE;
    
    // IP包在以太网解码器中已经解码过了，这里不需要重复解码
    if (!request->packet_info->ip_header) {
        fprintf(stderr, "IP解码处理器: IP头部指针为NULL\n");
        return -1;
    }
    
    return 0; // 处理成功
}

/**
 * @brief TCP解码处理器 - 处理TCP段
 * 
 * 作为IP解码处理器的子处理器，负责解析TCP段（预留接口）
 */
int tcp_decode_handler(void *req, void *ctx) {
    packet_request_t *request = (packet_request_t *)req;
    
    if (!request || !request->packet_info || !request->packet_info->ip_header) {
        fprintf(stderr, "TCP解码处理器: 无效的请求或未解析IP头\n");
        return -1;
    }
    
    // 确认IP协议是TCP
    if (request->packet_info->protocol != IPPROTO_TCP) {
        // 不是错误，只是不匹配，允许兄弟处理器处理
        return -1; 
    }
    
    // 设置当前处理类型
    request->handler_type = HANDLER_TYPE_TCP_DECODE;
    
    // TCP段解码已经在以太网->IP解码链中完成，这里无需重复解码
    if (!request->packet_info->tcp_header) {
        fprintf(stderr, "TCP解码处理器: TCP头部指针为NULL\n");
        return -1;
    }
    
    // 这里可以添加TCP协议特定的处理逻辑
    // 目前只是预留接口，返回成功
    return 0; 
}

/**
 * @brief UDP解码处理器 - 处理UDP段
 * 
 * 作为IP解码处理器的子处理器，负责解析UDP段（预留接口）
 */
int udp_decode_handler(void *req, void *ctx) {
    packet_request_t *request = (packet_request_t *)req;
    
    if (!request || !request->packet_info || !request->packet_info->ip_header) {
        fprintf(stderr, "UDP解码处理器: 无效的请求或未解析IP头\n");
        return -1;
    }
    
    // 确认IP协议是UDP
    if (request->packet_info->protocol != IPPROTO_UDP) {
        // 不是错误，只是不匹配，允许兄弟处理器处理
        return -1; 
    }
    
    // 设置当前处理类型
    request->handler_type = HANDLER_TYPE_UDP_DECODE;
    
    // UDP段解码已经在以太网->IP解码链中完成，这里无需重复解码
    if (!request->packet_info->udp_header) {
        fprintf(stderr, "UDP解码处理器: UDP头部指针为NULL\n");
        return -1;
    }
    
    // 这里可以添加UDP协议特定的处理逻辑
    // 目前只是预留接口，返回成功
    return 0;
}

/**
 * @brief 统计处理器 - 统计流量
 * 
 * 作为IP解码处理器的子处理器，负责统计流量数据
 */
int statistics_handler(void *req, void *ctx) {
    packet_request_t *request = (packet_request_t *)req;
    
    if (!request || !request->packet_info || !request->packet_info->ip_header) {
        fprintf(stderr, "统计处理器: 无效的请求或未解析IP头\n");
        return -1;
    }
    
    // 设置当前处理类型
    request->handler_type = HANDLER_TYPE_STAT;
    
    // 使用互斥锁保护流量分析器
    pthread_mutex_lock(&analyzer_mutex);
    
    // 统计流量
    if (!statistic_packet(
        traffic_analyzer,
        request->packet_info->src_ip,
        request->packet_info->dst_ip,
        request->local_ip,
        request->packet_info->total_size
    )) {
        fprintf(stderr, "统计处理器: 统计流量失败\n");
        pthread_mutex_unlock(&analyzer_mutex);
        return -1;
    }
    
    pthread_mutex_unlock(&analyzer_mutex);
    
    return 0; // 统计成功
}

/**
 * @brief 初始化网络数据包处理链
 * 
 * 创建并配置处理器节点，构建如图所示的责任链结构
 */
handler_node_t *init_packet_handlers() {
    // 创建以太网解码器（根节点）
    handler_node_t *eth_decoder = create_handler("以太网解码器", eth_decode_handler, NULL);
    if (!eth_decoder) {
        fprintf(stderr, "初始化数据包处理链: 创建以太网解码器失败\n");
        return NULL;
    }
    
    // 创建IP解码器
    handler_node_t *ip_decoder = create_handler("IP解码器", ip_decode_handler, NULL);
    if (!ip_decoder) {
        fprintf(stderr, "初始化数据包处理链: 创建IP解码器失败\n");
        destroy_handler(eth_decoder);
        return NULL;
    }
    
    // 创建"其他处理节点"（预留，使用空处理函数）
    handler_node_t *other_handler = create_handler("其他处理节点", dummy_handler, NULL);
    if (!other_handler) {
        fprintf(stderr, "初始化数据包处理链: 创建其他处理节点失败\n");
        destroy_handler(ip_decoder);
        destroy_handler(eth_decoder);
        return NULL;
    }
    
    // 创建TCP解码器
    handler_node_t *tcp_decoder = create_handler("TCP解码器", tcp_decode_handler, NULL);
    if (!tcp_decoder) {
        fprintf(stderr, "初始化数据包处理链: 创建TCP解码器失败\n");
        destroy_handler(other_handler);
        destroy_handler(ip_decoder);
        destroy_handler(eth_decoder);
        return NULL;
    }
    
    // 创建UDP解码器
    handler_node_t *udp_decoder = create_handler("UDP解码器", udp_decode_handler, NULL);
    if (!udp_decoder) {
        fprintf(stderr, "初始化数据包处理链: 创建UDP解码器失败\n");
        destroy_handler(tcp_decoder);
        destroy_handler(other_handler);
        destroy_handler(ip_decoder);
        destroy_handler(eth_decoder);
        return NULL;
    }
    
    // 创建统计处理器
    handler_node_t *stat_handler = create_handler("流量统计器", statistics_handler, NULL);
    if (!stat_handler) {
        fprintf(stderr, "初始化数据包处理链: 创建流量统计器失败\n");
        destroy_handler(udp_decoder);
        destroy_handler(tcp_decoder);
        destroy_handler(other_handler);
        destroy_handler(ip_decoder);
        destroy_handler(eth_decoder);
        return NULL;
    }
    
    // 创建其他功能处理器（预留，使用空处理函数）
    handler_node_t *other_feature = create_handler("其他功能", dummy_handler, NULL);
    if (!other_feature) {
        fprintf(stderr, "初始化数据包处理链: 创建其他功能失败\n");
        destroy_handler(stat_handler);
        destroy_handler(udp_decoder);
        destroy_handler(tcp_decoder);
        destroy_handler(other_handler);
        destroy_handler(ip_decoder);
        destroy_handler(eth_decoder);
        return NULL;
    }
    
    // 构建责任链结构
    // 1. 以太网解码器下添加IP解码器和其他处理节点
    if (add_child_handler(eth_decoder, ip_decoder) != 0 ||
        add_child_handler(eth_decoder, other_handler) != 0) {
        fprintf(stderr, "初始化数据包处理链: 添加以太网解码器子节点失败\n");
        goto cleanup;
    }
    
    // 2. IP解码器下添加TCP解码器、UDP解码器、流量统计器和其他功能
    if (add_child_handler(ip_decoder, tcp_decoder) != 0 ||
        add_child_handler(ip_decoder, udp_decoder) != 0 ||
        add_child_handler(ip_decoder, stat_handler) != 0 ||
        add_child_handler(ip_decoder, other_feature) != 0) {
        fprintf(stderr, "初始化数据包处理链: 添加IP解码器子节点失败\n");
        goto cleanup;
    }
    
    printf("数据包处理责任链初始化成功\n");
    print_handler_tree(eth_decoder, 0);
    return eth_decoder;
    
cleanup:
    // 清理已创建的处理器
    destroy_handler(other_feature);
    destroy_handler(stat_handler);
    destroy_handler(udp_decoder);
    destroy_handler(tcp_decoder);
    destroy_handler(other_handler);
    destroy_handler(ip_decoder);
    destroy_handler(eth_decoder);
    return NULL;
}

/**
 * @brief 销毁网络数据包处理链
 * 
 * 释放责任链中的所有处理器节点
 */
void destroy_packet_handlers(handler_node_t *root) {
    destroy_handler(root);
}

/**
 * @brief 处理数据包
 * 
 * 创建请求并启动责任链处理流程
 */
int handle_packet(handler_node_t *handlers, PacketInfo *packet_info, const char *local_ip) {
    if (!handlers || !packet_info || !local_ip) {
        fprintf(stderr, "处理数据包: 无效的参数\n");
        return -1;
    }
    
    // 创建请求
    packet_request_t *request = create_packet_request(packet_info, local_ip);
    if (!request) {
        fprintf(stderr, "处理数据包: 创建请求失败\n");
        return -1;
    }
    
    // 执行处理链
    int result = process_request(handlers, request, should_continue_processing);
    
    // 释放请求
    free_packet_request(request);
    
    return result;
}

/**
 * @brief 是否继续处理的判断函数
 * 
 * 决定责任链处理过程是否继续：
 * - 0或-1：继续处理
 * - 其他值：停止处理
 */
bool should_continue_processing(int result) {
    return (result == 0 || result == -1);
} 