#include "chain_of_responsibility.h"
#include <stdio.h>
#include <string.h>
#include <errno.h>

/**
 * @brief 创建处理器节点
 * 
 * 分配内存，初始化节点的各个字段，并复制处理器名称
 */
handler_node_t *create_handler(const char *name, handler_function handle, void *context) {
    if (!name || !handle) {
        fprintf(stderr, "创建处理器节点失败: 无效的参数\n");
        return NULL;
    }
    
    // 分配节点内存
    handler_node_t *node = (handler_node_t *)malloc(sizeof(handler_node_t));
    if (!node) {
        fprintf(stderr, "创建处理器节点失败: 内存分配错误 (errno: %d)\n", errno);
        return NULL;
    }
    
    // 分配并复制名称
    node->name = strdup(name);
    if (!node->name) {
        fprintf(stderr, "创建处理器节点失败: 名称内存分配错误 (errno: %d)\n", errno);
        free(node);
        return NULL;
    }
    
    // 初始化其他字段
    node->handle = handle;
    node->context = context;
    node->next_sibling = NULL;
    node->first_child = NULL;
    
    return node;
}

/**
 * @brief 添加子处理器
 * 
 * 如果父节点已有子节点，则将新子节点添加到子节点链表末尾
 */
int add_child_handler(handler_node_t *parent, handler_node_t *child) {
    if (!parent || !child) {
        fprintf(stderr, "添加子处理器失败: 无效的参数\n");
        return -1;
    }
    
    // 如果父节点没有子节点，直接添加
    if (!parent->first_child) {
        parent->first_child = child;
        return 0;
    }
    
    // 否则，找到最后一个子节点，添加为兄弟节点
    handler_node_t *last_child = parent->first_child;
    while (last_child->next_sibling) {
        last_child = last_child->next_sibling;
    }
    
    last_child->next_sibling = child;
    return 0;
}

/**
 * @brief 添加兄弟处理器
 * 
 * 将新兄弟节点添加到兄弟节点链表末尾
 */
int add_sibling_handler(handler_node_t *handler, handler_node_t *sibling) {
    if (!handler || !sibling) {
        fprintf(stderr, "添加兄弟处理器失败: 无效的参数\n");
        return -1;
    }
    
    // 找到最后一个兄弟节点
    handler_node_t *last_sibling = handler;
    while (last_sibling->next_sibling) {
        last_sibling = last_sibling->next_sibling;
    }
    
    last_sibling->next_sibling = sibling;
    return 0;
}

/**
 * @brief 执行处理链
 * 
 * 使用深度优先遍历处理器树，首先处理当前节点，然后处理子节点，最后处理兄弟节点
 */
int process_request(handler_node_t *handler, void *request, bool (*should_continue)(int)) {
    if (!handler) {
        return 0;  // 处理链为空，返回成功
    }
    
    int result = 0;
    
    // 执行当前处理器的处理函数
    result = handler->handle(request, handler->context);
    
    // 检查是否应该继续处理
    if (should_continue && !should_continue(result)) {
        // 根据should_continue函数的返回值决定是否停止处理
        return result;
    }
    
    // 如果有子节点，递归处理子节点（深度优先）
    if (handler->first_child) {
        result = process_request(handler->first_child, request, should_continue);
        
        // 检查子节点处理后是否应该继续处理
        if (should_continue && !should_continue(result)) {
            return result;
        }
    }
    
    // 如果有兄弟节点，递归处理兄弟节点（广度优先）
    if (handler->next_sibling) {
        result = process_request(handler->next_sibling, request, should_continue);
    }
    
    return result;
}

/**
 * @brief 销毁处理器节点及其所有子节点和兄弟节点
 * 
 * 递归释放整个处理器树，包括节点名称和节点本身
 */
void destroy_handler(handler_node_t *handler) {
    if (!handler) {
        return;
    }
    
    // 递归销毁子节点
    if (handler->first_child) {
        destroy_handler(handler->first_child);
    }
    
    // 保存下一个兄弟节点的指针
    handler_node_t *sibling = handler->next_sibling;
    
    // 释放当前节点
    free(handler->name);
    free(handler);
    
    // 递归销毁兄弟节点
    if (sibling) {
        destroy_handler(sibling);
    }
}

/**
 * @brief 查找处理器节点
 * 
 * 递归搜索处理器树，查找指定名称的节点
 */
handler_node_t *find_handler(handler_node_t *root, const char *name) {
    if (!root || !name) {
        return NULL;
    }
    
    // 检查当前节点
    if (strcmp(root->name, name) == 0) {
        return root;
    }
    
    // 递归检查子节点
    handler_node_t *found = NULL;
    if (root->first_child) {
        found = find_handler(root->first_child, name);
        if (found) {
            return found;
        }
    }
    
    // 递归检查兄弟节点
    if (root->next_sibling) {
        found = find_handler(root->next_sibling, name);
        if (found) {
            return found;
        }
    }
    
    return NULL;
}

/**
 * @brief 打印处理器树结构
 * 
 * 递归打印处理器树，用于调试
 */
void print_handler_tree(handler_node_t *handler, int level) {
    if (!handler) {
        return;
    }
    
    // 打印当前节点，使用缩进表示层级
    for (int i = 0; i < level; i++) {
        printf("  ");
    }
    printf("- %s\n", handler->name);
    
    // 递归打印子节点，增加缩进级别
    if (handler->first_child) {
        print_handler_tree(handler->first_child, level + 1);
    }
    
    // 递归打印兄弟节点，保持相同缩进级别
    if (handler->next_sibling) {
        print_handler_tree(handler->next_sibling, level);
    }
} 