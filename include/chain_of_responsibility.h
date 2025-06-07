#ifndef CHAIN_OF_RESPONSIBILITY_H
#define CHAIN_OF_RESPONSIBILITY_H

#include <stdlib.h>
#include <stdbool.h>

// 处理请求的函数指针类型
typedef int (*handler_function)(void *request, void *context);

// 处理器节点结构体
typedef struct handler_node {
    char *name;                        // 处理器名称
    handler_function handle;           // 处理函数
    void *context;                     // 处理器上下文
    struct handler_node *next_sibling; // 下一个兄弟节点
    struct handler_node *first_child;  // 第一个子节点
} handler_node_t;

/**
 * @brief 创建处理器节点
 * @param name 处理器名称
 * @param handle 处理函数
 * @param context 处理器上下文
 * @return 成功返回处理器节点指针，失败返回NULL
 */
handler_node_t *create_handler(const char *name, handler_function handle, void *context);

/**
 * @brief 添加子处理器
 * @param parent 父处理器
 * @param child 子处理器
 * @return 成功返回0，失败返回-1
 */
int add_child_handler(handler_node_t *parent, handler_node_t *child);

/**
 * @brief 添加兄弟处理器
 * @param handler 当前处理器
 * @param sibling 兄弟处理器
 * @return 成功返回0，失败返回-1
 */
int add_sibling_handler(handler_node_t *handler, handler_node_t *sibling);

/**
 * @brief 执行处理链
 * @param handler 处理器链的起始节点
 * @param request 请求数据
 * @param should_continue 指示是否继续处理的函数，NULL表示始终继续
 * @return 最后一个处理器的返回值
 */
int process_request(handler_node_t *handler, void *request, bool (*should_continue)(int));

/**
 * @brief 销毁处理器节点及其所有子节点和兄弟节点
 * @param handler 处理器节点
 */
void destroy_handler(handler_node_t *handler);

/**
 * @brief 查找处理器节点
 * @param root 根节点
 * @param name 处理器名称
 * @return 找到则返回处理器节点指针，否则返回NULL
 */
handler_node_t *find_handler(handler_node_t *root, const char *name);

/**
 * @brief 打印处理器树结构
 * @param handler 处理器节点
 * @param level 缩进级别
 */
void print_handler_tree(handler_node_t *handler, int level);

#endif // CHAIN_OF_RESPONSIBILITY_H 