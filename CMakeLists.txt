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


# 源文件
set(SOURCES 
    src/main.c
    src/packet_logger.c
    src/packet_parser.c
    src/packet_handlers.c
    src/chain_of_responsibility.c
    src/thread_pool.c
)

# 构建可执行文件
add_executable(network_sniffer ${SOURCES})

# 链接依赖库
target_link_libraries(network_sniffer ${PCAP_LIBRARY} pthread)