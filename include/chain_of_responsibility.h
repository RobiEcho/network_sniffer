#ifndef CHAIN_OF_RESPONSIBILITY_H
#define CHAIN_OF_RESPONSIBILITY_H

#include <stdlib.h>
#include <stdbool.h>

/**
 * @brief 处理请求的函数指针类型
 * 
 * @param request 请求对象，将被传递给处理函数
 * @param context 处理器上下文，包含处理器特定的数据
 * @return int 处理结果代码：
 *             0  - 处理成功，继续处理链
 *             -1 - 处理出错，继续处理链
 *             >0 - 其他值，停止处理链（由should_continue函数决定）
 */
typedef int (*handler_function)(void *request, void *context);

/**
 * @brief 处理器节点结构体 - 使用孩子兄弟树结构实现责任链
 * 
 * 孩子兄弟树是一种特殊的树结构，用于表示多叉树：
 * - 每个节点有两个指针：first_child和next_sibling
 * - first_child指向第一个子节点
 * - next_sibling指向同级的下一个兄弟节点
 */
typedef struct handler_node {
    char *name;                        // 处理器名称
    handler_function handle;           // 处理函数
    void *context;                     // 处理器上下文
    struct handler_node *next_sibling; // 下一个兄弟节点
    struct handler_node *first_child;  // 第一个子节点
} handler_node_t;

/**
 * @brief 创建处理器节点
 * 
 * @param name 处理器名称，将被复制
 * @param handle 处理函数，不能为NULL
 * @param context 处理器上下文，可以为NULL
 * @return 成功返回处理器节点指针，失败返回NULL
 */
handler_node_t *create_handler(const char *name, handler_function handle, void *context);

/**
 * @brief 添加子处理器
 * 
 * 此函数将child添加为parent的子节点。
 * 如果parent已有子节点，则child被添加为最后一个子节点的兄弟节点。
 * 
 * @param parent 父处理器
 * @param child 子处理器
 * @return 成功返回0，失败返回-1
 */
int add_child_handler(handler_node_t *parent, handler_node_t *child);

/**
 * @brief 添加兄弟处理器
 * 
 * 此函数将sibling添加为handler的兄弟节点。
 * sibling被添加到handler的兄弟链表的末尾。
 * 
 * @param handler 当前处理器
 * @param sibling 兄弟处理器
 * @return 成功返回0，失败返回-1
 */
int add_sibling_handler(handler_node_t *handler, handler_node_t *sibling);

/**
 * @brief 执行处理链
 * 
 * 该函数是责任链模式的核心，使用深度优先算法遍历处理器树：
 * 1. 先处理当前节点
 * 2. 检查should_continue函数决定是否继续处理
 * 3. 如果继续，递归处理所有子节点
 * 4. 如果继续，递归处理所有兄弟节点
 * 
 * @param handler 处理器链的起始节点
 * @param request 请求数据，将传递给每个处理器
 * @param should_continue 决定是否继续处理的函数，如果为NULL则总是继续
 *                        此函数接收处理器的返回值，返回true表示继续处理，false表示停止
 * @return 最后一个处理器的返回值，如果处理链为空则返回0
 */
int process_request(handler_node_t *handler, void *request, bool (*should_continue)(int));

/**
 * @brief 销毁处理器节点及其所有子节点和兄弟节点
 * 
 * 此函数递归释放整个处理器树，包括节点名称和节点本身。
 * 注意：不会释放context指针指向的内存，调用者负责管理context。
 * 
 * @param handler 处理器节点
 */
void destroy_handler(handler_node_t *handler);

/**
 * @brief 查找处理器节点
 * 
 * 此函数递归搜索整个处理器树，查找指定名称的节点。
 * 搜索顺序：当前节点 -> 子节点 -> 兄弟节点
 * 
 * @param root 根节点
 * @param name 处理器名称
 * @return 找到则返回处理器节点指针，否则返回NULL
 */
handler_node_t *find_handler(handler_node_t *root, const char *name);

/**
 * @brief 打印处理器树结构
 * 
 * 此函数递归打印整个处理器树的结构，便于调试。
 * 输出格式类似于目录树，使用缩进表示层级关系。
 * 
 * @param handler 处理器节点
 * @param level 缩进级别
 */
void print_handler_tree(handler_node_t *handler, int level);

#endif // CHAIN_OF_RESPONSIBILITY_H 