#ifndef THREAD_POOL_H
#define THREAD_POOL_H

#include <pthread.h>

// 任务结构体
typedef struct {
    void *(*function)(void *);  // 任务函数指针
    void *argument;            // 任务参数
} task_t;

// 任务队列节点
typedef struct task_node {
    task_t task;               // 任务
    struct task_node *next;    // 下一个节点
} task_node_t;

// 线程池结构体
typedef struct {
    pthread_mutex_t lock;      // 互斥锁，保护任务队列
    pthread_cond_t notify;     // 条件变量，用于通知线程有新任务
    pthread_t *threads;        // 工作线程数组
    task_node_t *queue_head;   // 任务队列头
    task_node_t *queue_tail;   // 任务队列尾
    int thread_count;          // 线程数量
    int queue_size;            // 当前队列中的任务数量
    int shutdown;              // 关闭标志
} thread_pool_t;

/**
 * @brief 创建线程池
 * @param thread_count 线程数量
 * @return 成功返回线程池指针，失败返回NULL
 */
thread_pool_t *thread_pool_create(int thread_count);

/**
 * @brief 向线程池添加任务
 * @param pool 线程池指针
 * @param function 任务函数
 * @param argument 任务参数
 * @return 成功返回0，失败返回-1
 */
int thread_pool_add_task(thread_pool_t *pool, void *(*function)(void *), void *argument);

/**
 * @brief 销毁线程池
 * @param pool 线程池指针
 * @return 成功返回0，失败返回-1
 */
int thread_pool_destroy(thread_pool_t *pool);

#endif // THREAD_POOL_H