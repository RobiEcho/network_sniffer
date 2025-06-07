#include <stdio.h>
#include <signal.h>
#include <pthread.h>
#include <pcap.h>
#include <netinet/in.h>
#include <unistd.h>
#include "packet_parser.h" 
#include "packet_logger.h"
#include "thread_pool.h"

volatile int running = 1;                 // 运行标志
pcap_t *handle = NULL;                    // 抓包句柄
TrafficAnalyzer *traffic_analyzer = NULL; // 流量分析结构体
char local_ip[INET_ADDRSTRLEN] = {0};     // 设备IP
thread_pool_t *thread_pool = NULL;        // 线程池
pthread_mutex_t analyzer_mutex = PTHREAD_MUTEX_INITIALIZER; // 流量分析器互斥锁

// 信号处理函数
void handle_signal(int signal) {
    printf("\n收到中断信号，正在停止抓包...\n");
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
        
        printf("销毁线程池...\n");
        thread_pool_destroy(thread_pool);
        thread_pool = NULL;
    }
    
    // 记录流量统计并释放资源
    if (traffic_analyzer != NULL) {
        printf("生成流量统计报告...\n");
        generate_logs_and_free(traffic_analyzer);
        traffic_analyzer = NULL;
    }
    
    // 关闭pcap句柄
    if (handle != NULL) {
        pcap_close(handle);
        handle = NULL;
    }
    
    // 销毁互斥锁
    pthread_mutex_destroy(&analyzer_mutex);
}

// 数据包解析线程
void *packet_parsing_callback(void *arg) {
    PacketInfo *packet_info = (PacketInfo *)arg;
    if (!packet_info) return NULL;
    
    Packetdelivery* data = parse_packet(packet_info);  // 解析数据包
    if (!data) {
        free_packet_info(packet_info);   // 释放数据包内存
        return NULL;
    }

    // 使用互斥锁保护流量统计操作
    pthread_mutex_lock(&analyzer_mutex);
    statistic_packet(traffic_analyzer, data->src_ip, data->dst_ip, local_ip, data->total_size);
    pthread_mutex_unlock(&analyzer_mutex);

    free_packet_delivery(data);      // 释放解析结果
    free_packet_info(packet_info);   // 释放数据包内存
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
        fprintf(stderr, "创建数据包信息结构体失败\n");
        return;
    }
    
    // 将任务添加到线程池
    if (thread_pool_add_task(thread_pool, packet_parsing_callback, packet_info) != 0) {
        fprintf(stderr, "添加任务到线程池失败\n");
        free_packet_info(packet_info);
    }
}

int main() {
    // 注册信号处理函数
    signal(SIGINT, handle_signal);
    
    // 注册退出清理函数
    atexit(cleanup_resources);
    
    // 获取本地IP
    if (!get_local_ip(local_ip, INET_ADDRSTRLEN)) {
        fprintf(stderr, "获取本地IP失败\n");
        return 1;
    }
    printf("本机IP: %s\n", local_ip);

    // 初始化流量统计器
    if (init_packet_analyzer(&traffic_analyzer) != 0) {
        fprintf(stderr, "初始化流量分析器失败\n");
        return 1;
    }
    
    // 初始化互斥锁
    if (pthread_mutex_init(&analyzer_mutex, NULL) != 0) {
        fprintf(stderr, "初始化互斥锁失败\n");
        return 1;
    }
    
    // 创建线程池，使用CPU核心数的两倍作为线程数
    int thread_count = 4; // 默认值
    #ifdef _SC_NPROCESSORS_ONLN
        int cpu_cores = sysconf(_SC_NPROCESSORS_ONLN);
        if (cpu_cores > 0) {
            thread_count = cpu_cores * 2;
        }
    #endif
    
    thread_pool = thread_pool_create(thread_count);
    if (thread_pool == NULL) {
        fprintf(stderr, "创建线程池失败\n");
        return 1;
    }
    printf("创建线程池成功，线程数: %d\n", thread_count);

    char errbuf[PCAP_ERRBUF_SIZE];      // 错误缓冲区
    pcap_if_t *devs;                    // 网卡设备列表
    struct bpf_program fp;              // 过滤器
    char filter_exp[] = "ip"; 
    
    // 获取所有网卡设备
    if (pcap_findalldevs(&devs, errbuf) == -1) {
        fprintf(stderr, "无法获取网卡设备列表: %s\n", errbuf);
        return 1;
    }
    
    // 检查是否有可用的网卡设备
    if (devs == NULL) {
        fprintf(stderr, "未找到可用的网卡设备\n");
        return 1;
    }
    
    // 打开网卡设备
    handle = pcap_open_live(devs->name, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
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
    
    pcap_freecode(&fp);
    pcap_freealldevs(devs);

    // 开始抓包
    printf("开始抓包...(按Ctrl+C停止)\n");
    int packet_count = 0;
    pcap_loop(handle, 0, packet_handler, (char *)&packet_count);
    printf("\n抓包结束，抓取到 %d 个数据包\n", packet_count);
    
    return 0;
}