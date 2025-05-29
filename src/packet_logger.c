#include "packet_logger.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

// 初始化流量分析器
TrafficAnalyzer* init_traffic_analyzer() {
    TrafficAnalyzer *analyzer = (TrafficAnalyzer*)malloc(sizeof(TrafficAnalyzer));
    if (!analyzer) return NULL;

    analyzer->head = NULL;
    analyzer->count = 0;

    return analyzer;
}

// 更新流量统计
void statistic_packet(TrafficAnalyzer *analyzer, const char *src_ip, const char *dst_ip,const char *local_ip, int size) {
    if (!analyzer) return;
    
    char remote_ip[INET_ADDRSTRLEN];
    int is_outgoing = 0; // 记录数据方向
    if (strcmp(src_ip, local_ip) == 0) {
        is_outgoing = 1; 
        strncpy(remote_ip, dst_ip, INET_ADDRSTRLEN - 1);
        remote_ip[INET_ADDRSTRLEN - 1] = '\0';
    } else {
        is_outgoing = 0;
        strncpy(remote_ip, src_ip, INET_ADDRSTRLEN - 1);
        remote_ip[INET_ADDRSTRLEN - 1] = '\0';
    }

    // 查找或创建统计节点
    TrafficStatNode *stat_node = find_or_create_stat_node(
        analyzer,
        local_ip,
        remote_ip
    );
    
    if (stat_node) {
        // 根据方向累加流量
        if (is_outgoing) {
            // 流出流量
            stat_node->stat.outgoing_bytes += size;
        } else {
            // 流入流量
            stat_node->stat.incoming_bytes += size;
        }
    }
}

// 查找或创建流量统计节点
TrafficStatNode* find_or_create_stat_node(TrafficAnalyzer *analyzer, const char *local_ip, const char *remote_ip) {
    // 先查找是否已存在该IP对的统计节点
    TrafficStatNode *current = analyzer->head;
    while (current) {
        if (strcmp(current->stat.local_ip, local_ip) == 0 &&
            strcmp(current->stat.remote_ip, remote_ip) == 0) {
            return current; // 找到匹配的节点
        }
        current = current->next;
    }

    // 未找到，创建新节点
    TrafficStatNode *node = (TrafficStatNode*)malloc(sizeof(TrafficStatNode));
    if (!node) return NULL;

    // 初始化节点数据
    strncpy(node->stat.local_ip, local_ip, INET_ADDRSTRLEN - 1);
    node->stat.local_ip[INET_ADDRSTRLEN - 1] = '\0';

    strncpy(node->stat.remote_ip, remote_ip, INET_ADDRSTRLEN - 1);
    node->stat.remote_ip[INET_ADDRSTRLEN - 1] = '\0';

    node->stat.outgoing_bytes = 0;
    node->stat.incoming_bytes = 0;

    // 添加到链表头部
    node->next = analyzer->head;
    analyzer->head = node;
    analyzer->count++;

    return node;
}

// 记录流量统计到日志
int write_traffic_stats_to_file(TrafficAnalyzer *analyzer) {
    if (!analyzer) return 0;

    // 生成文件名
    time_t now = time(NULL);
    struct tm *tm_info = localtime(&now);
    char filepath[50];
    strftime(filepath, sizeof(filepath), "%Y-%m-%dT%H:%M.txt", tm_info);

    // 打开文件
    FILE *file = fopen(filepath, "w");
    if (!file) return 0;

    // 写入文件头
    fprintf(file, "# 流量统计报告 - 生成时间: %s\n", ctime(&now));

    // 打印表格头部
    fprintf(file, "+-------------------+------------------+-----------------+------------------+------------------+\n");
    fprintf(file, "|      本机IP       |      其他IP       |     流出流量    |      流入流量     |      总流量       |\n");
    fprintf(file, "+-------------------+------------------+-----------------+------------------+------------------+\n");

    int count = 0;
    TrafficStatNode *current = analyzer->head;
    unsigned long total_outgoing = 0;
    unsigned long total_incoming = 0;

    // 获取当前时间戳
    char timestamp[20];
    strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", tm_info);

    // 写入每条统计记录（新格式）
    while (current) {
        fprintf(file, "| %-17s | %-16s | %'12lu字节 | %'12lu字节 | %'12lu字节 |\n",
                current->stat.local_ip,
                current->stat.remote_ip,
                current->stat.outgoing_bytes,
                current->stat.incoming_bytes,
                current->stat.outgoing_bytes + current->stat.incoming_bytes);

        fprintf(file, "+-------------------+------------------+------------------+-----------------+------------------+\n");

        total_outgoing += current->stat.outgoing_bytes;
        total_incoming += current->stat.incoming_bytes;
        current = current->next;
        count++;
    }

    // 写入总计
    fprintf(file, "\n# 统计总流量\n");
    fprintf(file, "# 流出: %lu 字节\n", total_outgoing);
    fprintf(file, "# 流入: %lu 字节\n", total_incoming);
    fprintf(file, "# 总计: %lu 字节\n", total_outgoing + total_incoming);

    // 关闭文件
    fclose(file);
    // printf("一共记录了 %d 个ip与本机进行数据交换\n", count);
    printf("流量统计报告已生成: %s\n",filepath);

    return count;
}

// 释放流量分析器及其所有记录
void free_traffic_analyzer(TrafficAnalyzer *analyzer) {
    if (!analyzer) return;
    // 释放所有节点
    TrafficStatNode *current = analyzer->head;
    TrafficStatNode *next;

    while (current) {
        next = current->next;
        free(current);
        current = next;
    }

    // 释放分析器
    free(analyzer);
}

// 初始化全局互斥锁和流量分析器
int init_packet_analyzer(TrafficAnalyzer **analyzer) {
    if (!analyzer) return -1;

    *analyzer = init_traffic_analyzer();
    if (!*analyzer) {
        fprintf(stderr, "初始化流量统计器失败\n");
        return -1;
    }

    return 0;
}

// 生成日志并释放资源
void generate_logs_and_free(TrafficAnalyzer *analyzer) {
    if (!analyzer) return;

    // 生成流量统计日志
    write_traffic_stats_to_file(analyzer);

    // 释放资源
    free_traffic_analyzer(analyzer);
}