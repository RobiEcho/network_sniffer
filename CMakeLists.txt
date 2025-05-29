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
file(GLOB SOURCES "src/*")

# 构建共享库
add_library(thread_pool SHARED src/thread_pool.c)
target_include_directories(thread_pool PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)

add_executable(network_sniffer ${SOURCES})

target_link_libraries(network_sniffer ${PCAP_LIBRARY} pthread)