cmake_minimum_required(VERSION 3.21)
project(ipk2 C)

set(CMAKE_C_STANDARD 99)

SET(CMAKE_MODULE_PATH "~/CLionProjects/ipk2")
find_package(PCAP REQUIRED)


add_executable(ipk2 ipk-sniffer.c errno.h dynamic_string.c)
target_link_libraries(ipk2 ${PCAP_LIBRARY})
