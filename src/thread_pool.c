#include "thread_pool.h"
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>

// 线程池中的工作线程函数
static void *thread_worker(void *arg) {
    thread_pool_t *pool = (thread_pool_t *)arg;
    task_t task;
    
    while (1) {
        // 清空任务信息，避免重用旧值
        memset(&task, 0, sizeof(task_t));
        
        // 获取互斥锁
        pthread_mutex_lock(&(pool->lock));
        
        // 等待任务队列有任务或者收到关闭信号
        while (pool->count == 0 && !pool->shutdown) {
            pthread_cond_wait(&(pool->notify), &(pool->lock));
        }
        
        // 如果线程池已关闭，退出线程
        if (pool->shutdown) {
            pthread_mutex_unlock(&(pool->lock));
            pthread_exit(NULL);
        }
        
        // 获取队列中的任务
        if (pool->count > 0) {
            // 获取队列头部的任务
            task.function = pool->task_queue[pool->head].function;
            task.argument = pool->task_queue[pool->head].argument;
            
            // 更新队列头索引
            pool->head = (pool->head + 1) % pool->queue_size;
            pool->count--;
        }
        
        // 释放互斥锁
        pthread_mutex_unlock(&(pool->lock));
        
        // 执行任务
        if (task.function != NULL) {
            (*task.function)(task.argument);
        }
    }
    
    return NULL;
}

// 创建线程池
thread_pool_t *thread_pool_create(int thread_count, int queue_size) {
    // 设置默认值
    if (thread_count <= 0) thread_count = 4;
    if (queue_size <= 0) queue_size = 64;
    
    // 分配线程池结构体内存
    thread_pool_t *pool = calloc(1, sizeof(thread_pool_t));
    if (!pool) return NULL;
    
    // 初始化基本属性
    pool->thread_count = thread_count;
    pool->queue_size = queue_size;
    pool->head = pool->tail = pool->count = 0;
    pool->shutdown = 0;
    
    // 分配任务队列内存
    pool->task_queue = calloc(queue_size, sizeof(task_t));
    if (!pool->task_queue) {
        free(pool);
        return NULL;
    }
    
    // 分配线程数组内存
    pool->threads = calloc(thread_count, sizeof(pthread_t));
    if (!pool->threads) {
        free(pool->task_queue);
        free(pool);
        return NULL;
    }
    
    // 初始化互斥锁和条件变量
    if (pthread_mutex_init(&(pool->lock), NULL) != 0 ||
        pthread_cond_init(&(pool->notify), NULL) != 0) {
        free(pool->threads);
        free(pool->task_queue);
        free(pool);
        return NULL;
    }
    
    // 创建工作线程
    for (int i = 0; i < thread_count; i++) {
        if (pthread_create(&(pool->threads[i]), NULL, thread_worker, pool) != 0) {
            // 创建线程失败，销毁线程池
            pool->thread_count = i; // 只销毁已创建的线程
            thread_pool_destroy(pool);
            return NULL;
        }
    }
    
    return pool;
}

// 向线程池添加任务
int thread_pool_add_task(thread_pool_t *pool, void *(*function)(void *), void *argument) {
    if (!pool || !function) return -1;
    
    // 获取互斥锁
    pthread_mutex_lock(&(pool->lock));
    
    // 检查线程池是否已关闭或队列是否已满
    if (pool->shutdown || pool->count >= pool->queue_size) {
        pthread_mutex_unlock(&(pool->lock));
        return -1;
    }
    
    // 添加任务到队列尾部
    pool->task_queue[pool->tail].function = function;
    pool->task_queue[pool->tail].argument = argument;
    pool->tail = (pool->tail + 1) % pool->queue_size;
    pool->count++;
    
    // 通知等待的线程有新任务
    pthread_cond_signal(&(pool->notify));
    
    // 释放互斥锁
    pthread_mutex_unlock(&(pool->lock));
    
    return 0;
}

// 销毁线程池
int thread_pool_destroy(thread_pool_t *pool) {
    if (!pool) return -1;
    
    // 获取互斥锁
    pthread_mutex_lock(&(pool->lock));
    
    // 检查线程池是否已关闭
    if (pool->shutdown) {
        pthread_mutex_unlock(&(pool->lock));
        return -1;
    }
    
    // 设置关闭标志
    pool->shutdown = 1;
    
    // 唤醒所有等待的线程
    pthread_cond_broadcast(&(pool->notify));
    
    // 释放互斥锁
    pthread_mutex_unlock(&(pool->lock));
    
    // 等待所有线程结束
    for (int i = 0; i < pool->thread_count; i++) {
        pthread_join(pool->threads[i], NULL);
    }
    
    // 清理资源
    if (pool->threads) free(pool->threads);
    if (pool->task_queue) free(pool->task_queue);
    
    pthread_mutex_destroy(&(pool->lock));
    pthread_cond_destroy(&(pool->notify));
    
    free(pool);
    return 0;
}

// 获取线程池中当前等待的任务数量
int thread_pool_get_queue_size(thread_pool_t *pool) {
    if (!pool) return -1;
    
    int size;
    pthread_mutex_lock(&(pool->lock));
    size = pool->count;
    pthread_mutex_unlock(&(pool->lock));
    
    return size;
}