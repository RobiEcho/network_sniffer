#include <stdio.h>
#include <stdint.h>
#include <signal.h>
#include <pthread.h>
#include <pcap.h>
#include <netinet/in.h>
#include <unistd.h>
#include "packet_parser.h" 
#include "traffic_analyzer.h"
#include "thread_pool.h"
#include "chain_of_responsibility.h"
#include "packet_handlers.h"

volatile int running = 1;                 // 运行标志
pcap_t *handle = NULL;                    // 抓包句柄
TrafficAnalyzer *traffic_analyzer = NULL; // 流量分析结构体
char local_ip[INET_ADDRSTRLEN] = {0};     // 设备IP
thread_pool_t *thread_pool = NULL;        // 线程池
pthread_mutex_t analyzer_mutex = PTHREAD_MUTEX_INITIALIZER; // 流量分析器互斥锁
handler_node_t *packet_handler_chain = NULL; // 数据包处理链

// 终止信号处理
void handle_signal(int signal) {
    running = 0;
    pcap_breakloop(handle);
}

// 资源清理函数
void cleanup_resources() {
    // 等待线程池中的剩余任务处理完成
    if (thread_pool != NULL) {
        int remaining_tasks = thread_pool_get_queue_size(thread_pool);
        if (remaining_tasks > 0) {
            printf("等待 %d 个剩余任务处理完成...\n", remaining_tasks);
            // 简单等待一段时间让任务处理完成
            sleep(1);
        }

        thread_pool_destroy(thread_pool);
        thread_pool = NULL;
    }

    // 销毁数据包处理链
    if (packet_handler_chain != NULL) {
        destroy_packet_handlers(packet_handler_chain);
        packet_handler_chain = NULL;
    }
    
    // 关闭pcap句柄
    if (handle != NULL) {
        pcap_close(handle);
        handle = NULL;
    }
    
    // 销毁互斥锁
    pthread_mutex_destroy(&analyzer_mutex);

    // 记录流量统计并释放资源
    if (traffic_analyzer != NULL) {
        
        generate_logs_and_free(traffic_analyzer);
        traffic_analyzer = NULL;
    }
    printf("流量统计报告已生成\n");
}

// 数据包处理线程回调函数（使用责任链模式）
void *packet_chain_callback(void *arg) {
    PacketInfo *packet_info = (PacketInfo *)arg;
    if (!packet_info) return NULL;
    
    // 使用责任链处理数据包
    handle_packet(packet_handler_chain, packet_info, local_ip);
    
    // 释放数据包信息
    free_packet_info(packet_info);
    return NULL;
}

// 抓包回调函数
void packet_handler(u_char *user, const struct pcap_pkthdr *h, const u_char *bytes) {
    int *packet_count = (int *)user;
    (*packet_count)++;
    
    // 如果程序已经收到中断信号，不再处理新的数据包
    if (!running) return;
    
    // 申请内存保存数据包，并传递给线程来处理
    PacketInfo *packet_info = create_packet_info(bytes, h->caplen);
    if (!packet_info) {
        fprintf(stderr, "数据包信息记录失败\n");
        return;
    }
    
    // 将任务添加到线程池，使用责任链模式的回调函数
    if (thread_pool_add_task(thread_pool, packet_chain_callback, packet_info) != 0) {
        fprintf(stderr, "添加任务到线程池失败\n");
        free_packet_info(packet_info);
    }
}

// 初始化基础资源函数
int init_resources() {
    // 获取本地IP
    if (!get_local_ip(local_ip, INET_ADDRSTRLEN)) {
        fprintf(stderr, "获取本地IP失败\n");
        return 1;
    }

    // 初始化流量统计器
    traffic_analyzer = init_packet_analyzer();
    if (traffic_analyzer == NULL) {
        fprintf(stderr, "初始化流量统计器失败\n");
        return 1;
    }
    
    // 初始化互斥锁
    if (pthread_mutex_init(&analyzer_mutex, NULL) != 0) {
        fprintf(stderr, "初始化互斥锁失败\n");
        return 1;
    }
    
    // 初始化数据包处理链
    packet_handler_chain = init_packet_handlers();
    if (packet_handler_chain == NULL) {
        fprintf(stderr, "初始化数据包处理链失败\n");
        return 1;
    }
    
    // 设置线程数为CPU核心数
    int thread_count = 4; // 默认值
    #ifdef _SC_NPROCESSORS_ONLN
        int cpu_cores = sysconf(_SC_NPROCESSORS_ONLN);
        if (cpu_cores > 0) {
            thread_count = cpu_cores;
        }
    #endif
    
    // 创建线程池
    thread_pool = thread_pool_create(thread_count, 1024); // 设置任务队列大小为1024
    if (thread_pool == NULL) {
        fprintf(stderr, "创建线程池失败\n");
        return 1;
    }

    return 0;
}

// 初始化网络抓包函数
int init_packet_capture() {
    char errbuf[PCAP_ERRBUF_SIZE];      // 错误缓冲区
    pcap_if_t *devs;                    // 网卡设备列表
    struct bpf_program fp;              // 过滤器
    char filter_exp[] = "ip";           // 过滤表达式
    
    // 获取所有网卡设备
    if (pcap_findalldevs(&devs, errbuf) == -1) {
        fprintf(stderr, "无法获取网卡设备列表: %s\n", errbuf);
        return 1;
    }
    
    // 打开网卡设备
    handle = pcap_open_live(devs->name, BUFSIZ, 1, 1000, errbuf);
    if (!handle) {
        fprintf(stderr, "无法打开网卡设备: %s\n", errbuf);
        pcap_freealldevs(devs);
        return 1;
    }
    
    // 设置过滤器
    if (pcap_compile(handle, &fp, filter_exp, 0, PCAP_NETMASK_UNKNOWN) == -1) {
        fprintf(stderr, "无法编译过滤器: %s\n", pcap_geterr(handle));
        pcap_freealldevs(devs);
        return 1;
    }
    
    if (pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "无法设置过滤器: %s\n", pcap_geterr(handle));
        pcap_freecode(&fp);
        pcap_freealldevs(devs);
        return 1;
    }
    
    // 释放网卡设备和过滤器
    pcap_freecode(&fp);
    pcap_freealldevs(devs);
    
    return 0;
}

int main() {
    // 注册终止信号处理函数
    signal(SIGINT, handle_signal);
    
    // 注册退出清理函数：当mian函数返回或程序通过exit()正常退出时调用
    atexit(cleanup_resources);
    
    // 初始化所有资源
    if (init_resources() != 0) {
        return 1;
    }
    
    // 初始化网络抓包
    if (init_packet_capture() != 0) {
        return 1;
    }

    // 开始抓包
    printf("开始抓包...(按Ctrl+C停止)\n");
    int packet_count = 0; // 抓包计数器
    pcap_loop(handle, 0, packet_handler, (char *)&packet_count);
    printf("\n抓包结束，抓取到 %d 个数据包\n", packet_count);
    
    // return前会调用cleanup_resources函数，释放资源
    return 0;
}