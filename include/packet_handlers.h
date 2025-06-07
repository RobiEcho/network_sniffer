#ifndef PACKET_HANDLERS_H
#define PACKET_HANDLERS_H

#include "chain_of_responsibility.h"
#include "packet_parser.h"

// 处理器类型常量
#define HANDLER_TYPE_FILTER    1  // 过滤处理器
#define HANDLER_TYPE_STAT      2  // 统计处理器
#define HANDLER_TYPE_LOGGER    3  // 日志处理器
#define HANDLER_TYPE_ANALYZER  4  // 分析处理器

// 数据包请求结构体
typedef struct {
    PacketInfo *packet_info;        // 数据包信息
    Packetdelivery *delivery_info;  // 数据包解析后的传输信息
    char local_ip[INET_ADDRSTRLEN]; // 本地IP
    int handler_type;               // 当前处理类型
    void *extra_data;               // 额外数据
} packet_request_t;

/**
 * @brief 初始化网络数据包处理链
 * @return 处理链的根节点
 */
handler_node_t *init_packet_handlers();

/**
 * @brief 销毁网络数据包处理链
 * @param root 处理链的根节点
 */
void destroy_packet_handlers(handler_node_t *root);

/**
 * @brief 创建数据包请求
 * @param packet_info 数据包信息
 * @param local_ip 本地IP
 * @return 成功返回请求指针，失败返回NULL
 */
packet_request_t *create_packet_request(PacketInfo *packet_info, const char *local_ip);

/**
 * @brief 释放数据包请求
 * @param request 请求指针
 */
void free_packet_request(packet_request_t *request);

/**
 * @brief 处理数据包
 * @param handlers 处理器链根节点
 * @param packet_info 数据包信息
 * @param local_ip 本地IP
 * @return 处理结果
 */
int handle_packet(handler_node_t *handlers, PacketInfo *packet_info, const char *local_ip);

/**
 * @brief 是否继续处理的判断函数
 * @param result 上一个处理器的结果
 * @return 继续返回true，中止返回false
 */
bool should_continue_processing(int result);

#endif // PACKET_HANDLERS_H 