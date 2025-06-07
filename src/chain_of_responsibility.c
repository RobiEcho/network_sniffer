#include "chain_of_responsibility.h"
#include <stdio.h>
#include <string.h>

// 创建处理器节点
handler_node_t *create_handler(const char *name, handler_function handle, void *context) {
    if (!name || !handle) {
        return NULL;
    }
    
    handler_node_t *node = (handler_node_t *)malloc(sizeof(handler_node_t));
    if (!node) {
        fprintf(stderr, "创建处理器节点失败: 内存分配错误\n");
        return NULL;
    }
    
    // 分配并复制名称
    node->name = strdup(name);
    if (!node->name) {
        fprintf(stderr, "创建处理器节点失败: 名称内存分配错误\n");
        free(node);
        return NULL;
    }
    
    node->handle = handle;
    node->context = context;
    node->next_sibling = NULL;
    node->first_child = NULL;
    
    return node;
}

// 添加子处理器
int add_child_handler(handler_node_t *parent, handler_node_t *child) {
    if (!parent || !child) {
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

// 添加兄弟处理器
int add_sibling_handler(handler_node_t *handler, handler_node_t *sibling) {
    if (!handler || !sibling) {
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

// 执行处理链
int process_request(handler_node_t *handler, void *request, bool (*should_continue)(int)) {
    if (!handler) {
        return 0;
    }
    
    int result = 0;
    handler_node_t *current = handler;
    
    // 先处理当前节点
    result = handler->handle(request, handler->context);
    
    // 检查是否应该继续处理
    if (should_continue && !should_continue(result)) {
        return result;
    }
    
    // 如果有子节点，先处理子节点
    if (handler->first_child) {
        result = process_request(handler->first_child, request, should_continue);
        
        // 检查是否应该继续处理
        if (should_continue && !should_continue(result)) {
            return result;
        }
    }
    
    // 最后处理兄弟节点
    if (handler->next_sibling) {
        result = process_request(handler->next_sibling, request, should_continue);
    }
    
    return result;
}

// 销毁处理器节点及其所有子节点和兄弟节点
void destroy_handler(handler_node_t *handler) {
    if (!handler) {
        return;
    }
    
    // 递归销毁子节点
    if (handler->first_child) {
        destroy_handler(handler->first_child);
    }
    
    // 递归销毁兄弟节点
    handler_node_t *sibling = handler->next_sibling;
    
    // 释放当前节点
    free(handler->name);
    free(handler);
    
    // 处理兄弟节点
    if (sibling) {
        destroy_handler(sibling);
    }
}

// 查找处理器节点
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

// 打印处理器树结构
void print_handler_tree(handler_node_t *handler, int level) {
    if (!handler) {
        return;
    }
    
    // 打印当前节点
    for (int i = 0; i < level; i++) {
        printf("  ");
    }
    printf("- %s\n", handler->name);
    
    // 递归打印子节点
    if (handler->first_child) {
        print_handler_tree(handler->first_child, level + 1);
    }
    
    // 递归打印兄弟节点
    if (handler->next_sibling) {
        print_handler_tree(handler->next_sibling, level);
    }
} 