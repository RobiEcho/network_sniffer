cmake_minimum_required(VERSION 3.10)
project(network_sniffer)

set(CMAKE_CXX_STANDARD 11)
set(CMAKE_C_COMPILER "gcc")

# 查找libpcap库
find_library(PCAP_LIBRARY pcap)
if(NOT PCAP_LIBRARY)
    message(FATAL_ERROR "libpcap库未找到")
endif()

include_directories(include)

# 构建线程池共享库
add_library(thread_pool SHARED src/thread_pool.c)
target_include_directories(thread_pool PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)

# 构建责任链模式共享库
add_library(chain_of_responsibility SHARED src/chain_of_responsibility.c)
target_include_directories(chain_of_responsibility PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)

# 源文件(排除thread_pool.c和chain_of_responsibility.c)
set(SOURCES 
    src/main.c
    src/packet_logger.c
    src/packet_parser.c
    src/packet_handlers.c
)

# 构建可执行文件
add_executable(network_sniffer ${SOURCES})

# 链接依赖库
target_link_libraries(network_sniffer ${PCAP_LIBRARY} pthread thread_pool chain_of_responsibility)