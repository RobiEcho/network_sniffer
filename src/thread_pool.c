#include "thread_pool.h"
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

// 线程池中的工作线程函数
static void *thread_worker(void *arg) {
    thread_pool_t *pool = (thread_pool_t *)arg;
    task_t task;
    
    while (1) {
        // 获取互斥锁
        pthread_mutex_lock(&(pool->lock));
        
        // 等待任务队列有任务或者收到关闭信号
        while (pool->queue_size == 0 && !pool->shutdown) {
            pthread_cond_wait(&(pool->notify), &(pool->lock));
        }
        
        // 如果线程池已关闭且任务队列为空，退出线程
        if (pool->shutdown && pool->queue_size == 0) {
            pthread_mutex_unlock(&(pool->lock));
            pthread_exit(NULL);
        }
        
        // 获取队列中的第一个任务
        task_node_t *task_node = pool->queue_head;
        if (task_node) {
            // 从队列中移除任务
            pool->queue_head = task_node->next;
            if (pool->queue_head == NULL) {
                pool->queue_tail = NULL;
            }
            pool->queue_size--;
            
            // 保存任务信息
            task.function = task_node->task.function;
            task.argument = task_node->task.argument;
            
            // 释放任务节点内存
            free(task_node);
        }
        
        // 释放互斥锁
        pthread_mutex_unlock(&(pool->lock));
        
        // 执行任务
        if (task.function != NULL) {
            (*(task.function))(task.argument);
        }
    }
    
    return NULL;
}

// 创建线程池
thread_pool_t *thread_pool_create(int thread_count) {
    if (thread_count <= 0) {
        thread_count = 4; // 默认创建4个线程
    }
    
    // 分配线程池结构体内存
    thread_pool_t *pool = (thread_pool_t *)malloc(sizeof(thread_pool_t));
    if (pool == NULL) {
        return NULL;
    }
    
    // 初始化线程池属性
    memset(pool, 0, sizeof(thread_pool_t));
    pool->thread_count = thread_count;
    pool->queue_size = 0;
    pool->queue_head = NULL;
    pool->queue_tail = NULL;
    pool->shutdown = 0;
    
    // 初始化互斥锁和条件变量
    if (pthread_mutex_init(&(pool->lock), NULL) != 0 ||
        pthread_cond_init(&(pool->notify), NULL) != 0) {
        free(pool);
        return NULL;
    }
    
    // 分配线程数组内存
    pool->threads = (pthread_t *)malloc(sizeof(pthread_t) * thread_count);
    if (pool->threads == NULL) {
        pthread_mutex_destroy(&(pool->lock));
        pthread_cond_destroy(&(pool->notify));
        free(pool);
        return NULL;
    }
    
    // 创建工作线程
    for (int i = 0; i < thread_count; i++) {
        if (pthread_create(&(pool->threads[i]), NULL, thread_worker, (void *)pool) != 0) {
            // 创建线程失败，销毁已创建的线程和资源
            thread_pool_destroy(pool);
            return NULL;
        }
    }
    
    return pool;
}

// 向线程池添加任务
int thread_pool_add_task(thread_pool_t *pool, void *(*function)(void *), void *argument) {
    if (pool == NULL || function == NULL) {
        return -1;
    }
    
    // 获取互斥锁
    pthread_mutex_lock(&(pool->lock));
    
    // 检查线程池是否已关闭
    if (pool->shutdown) {
        pthread_mutex_unlock(&(pool->lock));
        return -1;
    }
    
    // 创建新任务节点
    task_node_t *task = (task_node_t *)malloc(sizeof(task_node_t));
    if (task == NULL) {
        pthread_mutex_unlock(&(pool->lock));
        return -1;
    }
    
    // 初始化任务
    task->task.function = function;
    task->task.argument = argument;
    task->next = NULL;
    
    // 将任务添加到队列尾部
    if (pool->queue_head == NULL) {
        pool->queue_head = task;
    } else {
        pool->queue_tail->next = task;
    }
    pool->queue_tail = task;
    pool->queue_size++;
    
    // 通知等待的线程有新任务
    pthread_cond_signal(&(pool->notify));
    
    // 释放互斥锁
    pthread_mutex_unlock(&(pool->lock));
    
    return 0;
}

// 销毁线程池
int thread_pool_destroy(thread_pool_t *pool) {
    if (pool == NULL) {
        return -1;
    }
    
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
    
    // 释放资源
    free(pool->threads);
    
    // 释放任务队列中的所有任务
    task_node_t *current = pool->queue_head;
    task_node_t *next;
    while (current != NULL) {
        next = current->next;
        free(current);
        current = next;
    }
    
    // 销毁互斥锁和条件变量
    pthread_mutex_destroy(&(pool->lock));
    pthread_cond_destroy(&(pool->notify));
    
    // 释放线程池结构体
    free(pool);
    
    return 0;
}