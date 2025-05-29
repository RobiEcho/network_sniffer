#ifndef COMBINED_TRAFFIC_LOGGER_H
#define COMBINED_TRAFFIC_LOGGER_H

#include <pthread.h>
#include <netinet/in.h>

// 流量统计内容结构体
typedef struct {
    char local_ip[INET_ADDRSTRLEN];    // 本机IP
    char remote_ip[INET_ADDRSTRLEN];   // 远程IP
    unsigned long outgoing_bytes;       // 流出流量（字节）
    unsigned long incoming_bytes;       // 流入流量（字节）
} TrafficStat;

// 流量统计节点
typedef struct TrafficStatNode {
    TrafficStat stat;
    struct TrafficStatNode *next;
} TrafficStatNode;

// 流量统计器
typedef struct {
    TrafficStatNode *head;  // 头指针
    int count;              // 记录数量
} TrafficAnalyzer;

/**
 * @brief 更新流量统计
 * @param src_ip 数据包的源IP
 * @param dst_ip 数据包的目的IP
 * @param local_ip 本机IP
 * @param size 数据包大小(字节)
 */
void statistic_packet(TrafficAnalyzer *analyzer, const char *src_ip, const char *dst_ip,const char *local_ip, int size);

/**
 * @brief 初始化流量统计器
 * @return TrafficAnalyzer* 返回流量统计器指针
 */
TrafficAnalyzer* init_traffic_analyzer();

/**
 * @brief 将流量统计结果写入文件
 * @param analyzer 流量统计器
 * @return int 成功写入的记录数量
 */
int write_traffic_stats_to_file(TrafficAnalyzer *analyzer);

/**
 * @brief 释放流量统计器及其所有记录
 * @param analyzer 流量统计器
 */
void free_traffic_analyzer(TrafficAnalyzer *analyzer);

/**
 * @brief 查找或创建流量统计节点
 * @param analyzer 流量统计器
 * @param local_ip 本机IP
 * @param remote_ip 远程IP
 * @return TrafficStatNode* 返回找到或新创建的流量统计节点
 */
TrafficStatNode* find_or_create_stat_node(TrafficAnalyzer *analyzer, const char *local_ip, const char *remote_ip);

/**
 * @brief 流量分析器
 * @param analyzer 流量分析器
 * @return int 成功返回1，失败返回0
 */
int init_packet_analyzer(TrafficAnalyzer **analyzer);

/**
 * @brief 生成日志并释放资源
 * @param analyzer 流量分析器
 */
void generate_logs_and_free(TrafficAnalyzer *analyzer);

#endif // COMBINED_TRAFFIC_LOGGER_H