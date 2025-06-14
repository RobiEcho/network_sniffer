#include "traffic_analyzer.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <locale.h>
#include <errno.h>

/**
 * @brief 初始化流量分析器
 * 
 * 分配内存并初始化流量分析器结构体
 */
TrafficAnalyzer* init_traffic_analyzer() {
    TrafficAnalyzer *analyzer = (TrafficAnalyzer*)malloc(sizeof(TrafficAnalyzer));
    if (!analyzer) {
        fprintf(stderr, "初始化流量分析器失败: 内存分配错误 (errno: %d)\n", errno);
        return NULL;
    }

    analyzer->head = NULL;
    analyzer->count = 0;

    return analyzer;
}

/**
 * @brief 更新流量统计
 * 
 * 根据数据包的源IP和目的IP更新流量统计
 */
int statistic_packet(TrafficAnalyzer *analyzer, const char *src_ip, const char *dst_ip, const char *local_ip, int size) {
    if (!analyzer || !src_ip || !dst_ip || !local_ip || size <= 0) {
        fprintf(stderr, "更新流量统计失败: 无效的参数\n");
        return 0;
    }
    
    char remote_ip[INET_ADDRSTRLEN];
    int is_outgoing = 0; // 记录数据方向
    
    // 确定流量方向和远程IP
    if (strcmp(src_ip, local_ip) == 0) {
        is_outgoing = 1; 
        
        if (strlen(dst_ip) >= INET_ADDRSTRLEN) {
            fprintf(stderr, "更新流量统计失败: 目的IP过长\n");
            return 0;
        }
        
        strncpy(remote_ip, dst_ip, INET_ADDRSTRLEN - 1);
        remote_ip[INET_ADDRSTRLEN - 1] = '\0';
    } else {
        is_outgoing = 0;
        
        if (strlen(src_ip) >= INET_ADDRSTRLEN) {
            fprintf(stderr, "更新流量统计失败: 源IP过长\n");
            return 0;
        }
        
        strncpy(remote_ip, src_ip, INET_ADDRSTRLEN - 1);
        remote_ip[INET_ADDRSTRLEN - 1] = '\0';
    }

    // 查找或创建统计节点
    TrafficStatNode *stat_node = find_or_create_stat_node(
        analyzer,
        local_ip,
        remote_ip
    );
    
    if (!stat_node) {
        fprintf(stderr, "更新流量统计失败: 无法创建统计节点\n");
        return 0;
    }
    
    // 根据方向累加流量
    if (is_outgoing) {
        // 流出流量
        stat_node->stat.outgoing_bytes += size;
    } else {
        // 流入流量
        stat_node->stat.incoming_bytes += size;
    }
    
    return 1; // 成功
}

/**
 * @brief 查找或创建流量统计节点
 * 
 * 在流量统计器中查找特定IP对的节点，如果不存在则创建
 */
TrafficStatNode* find_or_create_stat_node(TrafficAnalyzer *analyzer, const char *local_ip, const char *remote_ip) {
    if (!analyzer || !local_ip || !remote_ip) {
        fprintf(stderr, "查找或创建流量统计节点失败: 无效的参数\n");
        return NULL;
    }
    
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
    if (!node) {
        fprintf(stderr, "创建流量统计节点失败: 内存分配错误 (errno: %d)\n", errno);
        return NULL;
    }

    // 初始化节点数据，确保正确复制字符串
    if (strlen(local_ip) >= INET_ADDRSTRLEN || strlen(remote_ip) >= INET_ADDRSTRLEN) {
        fprintf(stderr, "创建流量统计节点失败: IP地址过长\n");
        free(node);
        return NULL;
    }
    
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

/**
 * @brief 记录流量统计到日志文件
 * 
 * 生成包含所有流量统计数据的文本文件
 */
int write_traffic_stats_to_file(TrafficAnalyzer *analyzer) {
    if (!analyzer) {
        fprintf(stderr, "记录流量统计失败: 无效的分析器\n");
        return 0;
    }

    // 设置本地化，以支持数字格式化
    setlocale(LC_NUMERIC, "");
    
    // 生成文件名，使用当前时间
    time_t now = time(NULL);
    if (now == (time_t)-1) {
        fprintf(stderr, "记录流量统计失败: 获取当前时间失败 (errno: %d)\n", errno);
        return 0;
    }
    
    struct tm *tm_info = localtime(&now);
    if (!tm_info) {
        fprintf(stderr, "记录流量统计失败: 转换时间格式失败 (errno: %d)\n", errno);
        return 0;
    }
    
    char filepath[50];
    if (strftime(filepath, sizeof(filepath), "%Y-%m-%dT%H:%M.txt", tm_info) == 0) {
        fprintf(stderr, "记录流量统计失败: 生成文件名失败\n");
        return 0;
    }

    // 打开文件
    FILE *file = fopen(filepath, "w");
    if (!file) {
        fprintf(stderr, "记录流量统计失败: 无法创建文件 %s (errno: %d)\n", filepath, errno);
        return 0;
    }

    // 写入文件头
    char time_str[50];
    if (ctime_r(&now, time_str) == NULL) {
        fprintf(stderr, "记录流量统计失败: 格式化时间失败 (errno: %d)\n", errno);
        fclose(file);
        return 0;
    }
    
    // 移除ctime返回的换行符
    size_t len = strlen(time_str);
    if (len > 0 && time_str[len-1] == '\n') {
        time_str[len-1] = '\0';
    }
    
    fprintf(file, "# 流量统计报告 - 生成时间: %s\n\n", time_str);

    // 打印表格头部
    fprintf(file, "+-------------------+------------------+------------------+-----------------+------------------+\n");
    fprintf(file, "|      本机IP       |      其他IP       |     流出流量     |     流入流量     |      总流量       |\n");
    fprintf(file, "+-------------------+------------------+------------------+-----------------+------------------+\n");

    int count = 0;
    TrafficStatNode *current = analyzer->head;
    unsigned long total_outgoing = 0;
    unsigned long total_incoming = 0;

    // 写入每条统计记录
    while (current) {
        fprintf(file, "| %-17s | %-16s | %12lu字节 | %12lu字节 | %12lu字节 |\n",
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
    printf("流量统计报告已生成: %s\n", filepath);

    return count;
}

/**
 * @brief 释放流量分析器及其所有记录
 * 
 * 递归释放所有流量统计节点和流量统计器本身
 */
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

/**
 * @brief 初始化流量分析器
 * 
 * 创建并初始化流量分析器
 */
TrafficAnalyzer* init_packet_analyzer() {
    TrafficAnalyzer *analyzer = init_traffic_analyzer();
    if (!analyzer) {
        fprintf(stderr, "初始化流量分析器失败: 创建流量统计器失败\n");
        return NULL;
    }

    return analyzer;
}

/**
 * @brief 生成日志并释放资源
 * 
 * 将流量统计数据写入文件并释放资源（用于程序结束时）
 */
void generate_logs_and_free(TrafficAnalyzer *analyzer) {
    if (!analyzer) return;

    // 生成流量统计日志
    if (write_traffic_stats_to_file(analyzer) == 0) {
        fprintf(stderr, "生成日志并释放资源: 写入流量统计文件失败\n");
    }

    // 释放资源
    free_traffic_analyzer(analyzer);
}