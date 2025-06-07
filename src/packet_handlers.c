#include "packet_handlers.h"
#include "packet_logger.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

extern TrafficAnalyzer *traffic_analyzer; // 从main.c引入流量分析器
extern pthread_mutex_t analyzer_mutex;    // 从main.c引入互斥锁

// 过滤处理器上下文
typedef struct {
    char filter_ip[INET_ADDRSTRLEN];  // 过滤的IP地址
    int filter_type;                  // 过滤类型：1-源IP，2-目的IP
} filter_context_t;

// 创建数据包请求
packet_request_t *create_packet_request(PacketInfo *packet_info, const char *local_ip) {
    if (!packet_info || !local_ip) {
        return NULL;
    }
    
    packet_request_t *request = (packet_request_t *)malloc(sizeof(packet_request_t));
    if (!request) {
        fprintf(stderr, "创建数据包请求失败: 内存分配错误\n");
        return NULL;
    }
    
    request->packet_info = packet_info;
    request->delivery_info = NULL;
    strncpy(request->local_ip, local_ip, INET_ADDRSTRLEN - 1);
    request->local_ip[INET_ADDRSTRLEN - 1] = '\0';
    request->handler_type = 0;
    request->extra_data = NULL;
    
    return request;
}

// 释放数据包请求
void free_packet_request(packet_request_t *request) {
    if (!request) {
        return;
    }
    
    // 释放解析信息
    if (request->delivery_info) {
        free_packet_delivery(request->delivery_info);
    }
    
    // 不释放packet_info，由调用者负责
    
    free(request);
}

// 解析处理器 - 提取源IP和目的IP
int parse_handler(void *req, void *ctx) {
    packet_request_t *request = (packet_request_t *)req;
    if (!request || !request->packet_info) {
        return -1;
    }
    
    // 设置当前处理类型
    request->handler_type = HANDLER_TYPE_FILTER;
    
    // 解析数据包
    request->delivery_info = parse_packet(request->packet_info);
    if (!request->delivery_info) {
        return -1;
    }
    
    return 0;
}

// IP过滤处理器 - 根据指定IP进行过滤
int filter_handler(void *req, void *ctx) {
    packet_request_t *request = (packet_request_t *)req;
    filter_context_t *filter_ctx = (filter_context_t *)ctx;
    
    if (!request || !request->delivery_info || !filter_ctx) {
        return -1;
    }
    
    // 设置当前处理类型
    request->handler_type = HANDLER_TYPE_FILTER;
    
    // 根据过滤类型进行过滤
    if (filter_ctx->filter_type == 1) {
        // 过滤源IP
        if (strcmp(request->delivery_info->src_ip, filter_ctx->filter_ip) != 0) {
            return 1; // 不匹配，返回1表示跳过后续处理
        }
    } else if (filter_ctx->filter_type == 2) {
        // 过滤目的IP
        if (strcmp(request->delivery_info->dst_ip, filter_ctx->filter_ip) != 0) {
            return 1; // 不匹配，返回1表示跳过后续处理
        }
    }
    
    return 0; // 匹配，继续处理
}

// 统计处理器 - 统计流量
int statistics_handler(void *req, void *ctx) {
    packet_request_t *request = (packet_request_t *)req;
    
    if (!request || !request->delivery_info) {
        return -1;
    }
    
    // 设置当前处理类型
    request->handler_type = HANDLER_TYPE_STAT;
    
    // 使用互斥锁保护流量分析器
    pthread_mutex_lock(&analyzer_mutex);
    
    // 统计流量
    statistic_packet(
        traffic_analyzer,
        request->delivery_info->src_ip,
        request->delivery_info->dst_ip,
        request->local_ip,
        request->delivery_info->total_size
    );
    
    pthread_mutex_unlock(&analyzer_mutex);
    
    return 0;
}

// 日志处理器 - 记录数据包信息
int logger_handler(void *req, void *ctx) {
    packet_request_t *request = (packet_request_t *)req;
    
    if (!request || !request->delivery_info) {
        return -1;
    }
    
    // 设置当前处理类型
    request->handler_type = HANDLER_TYPE_LOGGER;
    
    // 输出数据包信息
    printf("数据包: %s -> %s, 大小: %d字节\n",
           request->delivery_info->src_ip,
           request->delivery_info->dst_ip,
           request->delivery_info->total_size);
    
    return 0;
}

// 初始化网络数据包处理链
handler_node_t *init_packet_handlers() {
    // 创建解析处理器
    handler_node_t *root = create_handler("解析处理器", parse_handler, NULL);
    if (!root) {
        fprintf(stderr, "创建解析处理器失败\n");
        return NULL;
    }
    
    // 创建统计处理器
    handler_node_t *stat_handler = create_handler("统计处理器", statistics_handler, NULL);
    if (!stat_handler) {
        fprintf(stderr, "创建统计处理器失败\n");
        destroy_handler(root);
        return NULL;
    }
    
    // 添加统计处理器为解析处理器的子节点
    if (add_child_handler(root, stat_handler) != 0) {
        fprintf(stderr, "添加统计处理器失败\n");
        destroy_handler(stat_handler);
        destroy_handler(root);
        return NULL;
    }
    
    // 创建日志处理器
    handler_node_t *log_handler = create_handler("日志处理器", logger_handler, NULL);
    if (!log_handler) {
        fprintf(stderr, "创建日志处理器失败\n");
        destroy_handler(root);
        return NULL;
    }
    
    // 添加日志处理器为统计处理器的兄弟节点
    if (add_sibling_handler(stat_handler, log_handler) != 0) {
        fprintf(stderr, "添加日志处理器失败\n");
        destroy_handler(log_handler);
        destroy_handler(root);
        return NULL;
    }
    
    // 创建并添加一个过滤处理器示例（过滤特定IP地址）
    filter_context_t *filter_ctx = (filter_context_t *)malloc(sizeof(filter_context_t));
    if (filter_ctx) {
        // 设置过滤为源IP 8.8.8.8
        strncpy(filter_ctx->filter_ip, "8.8.8.8", INET_ADDRSTRLEN - 1);
        filter_ctx->filter_ip[INET_ADDRSTRLEN - 1] = '\0';
        filter_ctx->filter_type = 1; // 过滤源IP
        
        handler_node_t *filter_handler_node = create_handler("IP过滤处理器", filter_handler, filter_ctx);
        if (filter_handler_node) {
            // 添加为日志处理器的子节点
            if (add_child_handler(log_handler, filter_handler_node) != 0) {
                fprintf(stderr, "添加IP过滤处理器失败\n");
                destroy_handler(filter_handler_node);
            }
        }
    }
    
    return root;
}

// 销毁网络数据包处理链
void destroy_packet_handlers(handler_node_t *root) {
    destroy_handler(root);
}

// 处理数据包
int handle_packet(handler_node_t *handlers, PacketInfo *packet_info, const char *local_ip) {
    if (!handlers || !packet_info || !local_ip) {
        return -1;
    }
    
    // 创建请求
    packet_request_t *request = create_packet_request(packet_info, local_ip);
    if (!request) {
        return -1;
    }
    
    // 执行处理链
    int result = process_request(handlers, request, should_continue_processing);
    
    // 释放请求
    free_packet_request(request);
    
    return result;
}

// 是否继续处理的判断函数
bool should_continue_processing(int result) {
    // 返回值为0或-1时继续处理，其他值停止处理
    return (result == 0 || result == -1);
} 