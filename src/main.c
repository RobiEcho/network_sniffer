#include <stdio.h>
#include <signal.h>
#include <pthread.h>
#include <pcap.h>
#include <netinet/in.h>
#include "packet_parser.h" 
#include "packet_logger.h"
#include "thread_pool.h"

volatile int running = 1;                 // 运行标志
pcap_t *handle = NULL;                    // 抓包句柄
TrafficAnalyzer *traffic_analyzer = NULL; // 流量分析结构体
char local_ip[INET_ADDRSTRLEN] = {0};     // 设备IP
thread_pool_t *thread_pool = NULL;        // 线程池

// 信号处理函数
void handle_signal(int signal) {
    running = 0;
    pcap_breakloop(handle);
}

// 数据包解析线程
void *packet_parsing_callback(void *arg) {
    PacketInfo *packet_info = (PacketInfo *)arg;
    Packetdelivery* data = parse_packet(packet_info);  // 解析数据包
    if (!data) {
        free_packet_info(packet_info);   // 释放数据包内存
        return NULL;
    }

    //统计流量
    statistic_packet(traffic_analyzer, data->src_ip, data->dst_ip, local_ip, data->total_size);

    free_packet_delivery(data);      // 释放解析结果
    free_packet_info(packet_info);   // 释放数据包内存
    return NULL;
}

// 抓包回调函数
void packet_handler(u_char *user, const struct pcap_pkthdr *h, const u_char *bytes) {
    int *packet_count = (int *)user;
    (*packet_count)++;
    // 申请内存保存数据包，并传递给线程来处理
    PacketInfo *packet_info = create_packet_info(bytes, h->caplen);
    if (!packet_info) return;
    
    // 将任务添加到线程池，而不是每次创建新线程
    thread_pool_add_task(thread_pool, packet_parsing_callback, packet_info);
}

int main() {
    if (!get_local_ip(local_ip, INET_ADDRSTRLEN)) {
        fprintf(stderr, "获取本地IP失败\n");
        return 0;
    }

    // 流量统计器
    if (init_packet_analyzer(&traffic_analyzer) != 0) {
        fprintf(stderr, "初始化失败\n");
        return 1;
    }
    
    // 创建线程池，使用4个工作线程
    thread_pool = thread_pool_create(4);
    if (thread_pool == NULL) {
        fprintf(stderr, "创建线程池失败\n");
        return 1;
    }
    
    // 注册信号
    signal(SIGINT, handle_signal);

    char errbuf[PCAP_ERRBUF_SIZE];      // 错误缓冲区
    pcap_if_t *devs;                    // 网卡设备列表
    struct bpf_program fp;              // 过滤器
    char filter_exp[] = "ip"; 
    
    // 获取所有网卡设备
    if (pcap_findalldevs(&devs, errbuf) == -1) {
        fprintf(stderr, "无法获取网卡设备列表: %s\n", errbuf);
        return 1;
    }
    
    // 打开网卡设备
    handle = pcap_open_live(devs->name, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        printf("无法打开网卡设备: %s\n", errbuf);
        pcap_freealldevs(devs);
        return 0;
    }
    pcap_compile(handle, &fp, filter_exp, 0, PCAP_NETMASK_UNKNOWN);
    pcap_setfilter(handle, &fp);

    // 开始抓包
    printf("开始抓包...\n");
    int packet_count = 0;
    pcap_loop(handle, 0, packet_handler, (char *)&packet_count);
    printf("\n抓包结束，抓取到 %d 个数据包\n", packet_count);
    
    // 按下ctrl+c触发信号，停止抓包，并记录包的数据流量
    generate_logs_and_free(traffic_analyzer);
    
    // 销毁线程池
    thread_pool_destroy(thread_pool);

    // 释放网卡设备
    pcap_close(handle);
    pcap_freealldevs(devs);

    return 0;
}