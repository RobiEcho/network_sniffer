#ifndef TRAFFIC_ANALYZER_H
#define TRAFFIC_ANALYZER_H

#include <pthread.h>
#include <netinet/in.h>

/**
 * @brief 流量统计内容结构体
 * 
 * 存储特定IP对（本地IP和远程IP）之间的流量数据
 */
typedef struct {
    char local_ip[INET_ADDRSTRLEN];    // 本机IP
    char remote_ip[INET_ADDRSTRLEN];   // 远程IP
    unsigned long outgoing_bytes;       // 流出流量（字节）
    unsigned long incoming_bytes;       // 流入流量（字节）
} TrafficStat;

/**
 * @brief 流量统计节点
 * 
 * 哈希表中的节点，用于处理哈希冲突
 */
typedef struct TrafficStatNode {
    TrafficStat stat;                  // 流量统计数据
    struct TrafficStatNode *next;      // 冲突链表的下一个节点
} TrafficStatNode;

/**
 * @brief 哈希表大小
 */
#define HASH_TABLE_SIZE 1024

/**
 * @brief 流量统计器
 * 
 * 使用哈希表管理所有流量统计记录的主结构
 */
typedef struct {
    TrafficStatNode *buckets[HASH_TABLE_SIZE];  // 哈希桶
    int count;                                  // 记录数量
} TrafficAnalyzer;

/**
 * @brief 初始化流量统计器
 * 
 * 分配并初始化一个新的流量统计器
 * 
 * @return TrafficAnalyzer* 返回流量统计器指针，失败返回NULL
 */
TrafficAnalyzer* init_traffic_analyzer();

/**
 * @brief 更新流量统计
 * 
 * 根据数据包的源IP和目的IP更新流量统计
 * 
 * @param analyzer 流量统计器
 * @param src_ip 数据包的源IP
 * @param dst_ip 数据包的目的IP
 * @param local_ip 本机IP
 * @param size 数据包大小(字节)
 * @return int 成功返回0，失败返回-1
 */
int statistic_packet(TrafficAnalyzer *analyzer, const char *src_ip, const char *dst_ip, const char *local_ip, int size);

/**
 * @brief 将流量统计结果写入文件
 * 
 * 生成一个包含所有流量统计数据的文本文件
 * 
 * @param analyzer 流量统计器
 * @return int 成功写入的记录数量，失败返回0
 */
int write_traffic_stats_to_file(TrafficAnalyzer *analyzer);

/**
 * @brief 释放流量统计器及其所有记录
 * 
 * 递归释放所有流量统计节点和流量统计器本身
 * 
 * @param analyzer 流量统计器
 */
void free_traffic_analyzer(TrafficAnalyzer *analyzer);

/**
 * @brief 查找或创建流量统计节点
 * 
 * 在流量统计器中查找特定IP对的节点，如果不存在则创建
 * 
 * @param analyzer 流量统计器
 * @param local_ip 本机IP
 * @param remote_ip 远程IP
 * @return TrafficStatNode* 返回找到或新创建的流量统计节点，失败返回NULL
 */
TrafficStatNode* find_or_create_stat_node(TrafficAnalyzer *analyzer, const char *local_ip, const char *remote_ip);

/**
 * @brief 计算IP对的哈希值
 * 
 * 根据本地IP和远程IP计算哈希值
 * 
 * @param local_ip 本机IP
 * @param remote_ip 远程IP
 * @return unsigned int 返回哈希值
 */
unsigned int hash_ip_pair(const char *local_ip, const char *remote_ip);

/**
 * @brief 初始化流量分析器
 * 
 * 创建并初始化流量分析器
 * 
 * @return TrafficAnalyzer* 成功返回流量分析器指针，失败返回NULL
 */
TrafficAnalyzer* init_packet_analyzer();

/**
 * @brief 生成日志并释放资源
 * 
 * 将流量统计数据写入文件并释放资源（用于程序结束时）
 * 
 * @param analyzer 流量分析器
 */
void generate_logs_and_free(TrafficAnalyzer *analyzer);

#endif // TRAFFIC_ANALYZER_H