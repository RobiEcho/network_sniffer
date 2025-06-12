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
 * @brief 解析处理器 - 提取源IP和目的IP
 * 
 * 责任链中的第一个处理器，负责解析数据包
 */
int parse_handler(void *req, void *ctx) {
    packet_request_t *request = (packet_request_t *)req;
    if (!request || !request->packet_info) {
        fprintf(stderr, "解析处理器: 无效的请求\n");
        return -1;
    }
    
    // 设置当前处理类型
    request->handler_type = HANDLER_TYPE_PARSE;
    
    // 解析数据包（将结果直接存储在packet_info中）
    if (!parse_packet(request->packet_info)) {
        fprintf(stderr, "解析处理器: 解析数据包失败\n");
        return -1;
    }
    
    return 0; // 解析成功
}

/**
 * @brief 统计处理器 - 统计流量
 * 
 * 责任链中的第二个处理器，负责统计流量数据
 */
int statistics_handler(void *req, void *ctx) {
    packet_request_t *request = (packet_request_t *)req;
    
    if (!request || !request->packet_info || !request->packet_info->is_parsed) {
        fprintf(stderr, "统计处理器: 无效的请求或数据包未解析\n");
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
 * 创建并配置处理器节点，构建责任链结构
 */
handler_node_t *init_packet_handlers() {
    // 创建解析处理器
    handler_node_t *root = create_handler("解析处理器", parse_handler, NULL);
    if (!root) {
        fprintf(stderr, "初始化数据包处理链: 创建解析处理器失败\n");
        return NULL;
    }
    
    // 创建统计处理器
    handler_node_t *stat_handler = create_handler("统计处理器", statistics_handler, NULL);
    if (!stat_handler) {
        fprintf(stderr, "初始化数据包处理链: 创建统计处理器失败\n");
        destroy_handler(root);
        return NULL;
    }
    
    // 添加统计处理器为解析处理器的子节点
    if (add_child_handler(root, stat_handler) != 0) {
        fprintf(stderr, "初始化数据包处理链: 添加统计处理器失败\n");
        destroy_handler(stat_handler);
        destroy_handler(root);
        return NULL;
    }
    
    return root;
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