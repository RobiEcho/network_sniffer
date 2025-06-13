#ifndef PACKET_HANDLERS_H
#define PACKET_HANDLERS_H

#include "chain_of_responsibility.h"
#include "packet_parser.h"

// 处理器类型常量
#define HANDLER_TYPE_ETH_DECODE  1  // 以太网解码器
#define HANDLER_TYPE_IP_DECODE   2  // IP解码器
#define HANDLER_TYPE_TCP_DECODE  3  // TCP解码器
#define HANDLER_TYPE_UDP_DECODE  4  // UDP解码器
#define HANDLER_TYPE_STAT        5  // 统计处理器

/**
 * @brief 数据包请求结构体，用于在责任链中传递数据包信息
 * 
 * 该结构体包含了处理数据包所需的所有信息，作为责任链各处理器之间的通信媒介
 */
typedef struct {
    PacketInfo *packet_info;        // 数据包信息（包含原始数据和解析结果）
    char local_ip[INET_ADDRSTRLEN]; // 本地IP地址
    int handler_type;               // 当前处理类型（标识当前处理阶段）
    void *extra_data;               // 额外数据（可用于处理器间传递特定信息）
} packet_request_t;

/**
 * @brief 初始化网络数据包处理链
 * 
 * 创建并配置处理器节点，构建责任链结构
 * 
 * @return 处理链的根节点，失败返回NULL
 */
handler_node_t *init_packet_handlers();

/**
 * @brief 销毁网络数据包处理链
 * 
 * 释放责任链中的所有处理器节点
 * 
 * @param root 处理链的根节点
 */
void destroy_packet_handlers(handler_node_t *root);

/**
 * @brief 创建数据包请求
 * 
 * 分配并初始化一个数据包请求结构体
 * 
 * @param packet_info 数据包信息，不会被复制，只存储指针
 * @param local_ip 本地IP地址，会被复制到请求中
 * @return 成功返回请求指针，失败返回NULL
 */
packet_request_t *create_packet_request(PacketInfo *packet_info, const char *local_ip);

/**
 * @brief 释放数据包请求
 * 
 * 释放请求结构体，但不释放packet_info（由调用者负责）
 * 
 * @param request 请求指针
 */
void free_packet_request(packet_request_t *request);

/**
 * @brief 处理数据包
 * 
 * 创建请求并启动责任链处理流程
 * 
 * @param handlers 处理器链根节点
 * @param packet_info 数据包信息
 * @param local_ip 本地IP地址
 * @return 处理结果：0表示成功，-1表示失败
 */
int handle_packet(handler_node_t *handlers, PacketInfo *packet_info, const char *local_ip);

/**
 * @brief 是否继续处理的判断函数
 * 
 * 决定责任链处理过程是否继续
 * 
 * @param result 上一个处理器的结果
 * @return 继续返回true，中止返回false
 */
bool should_continue_processing(int result);

#endif // PACKET_HANDLERS_H 