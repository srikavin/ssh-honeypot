cmake_minimum_required(VERSION 3.10)
project(ssh_honeypot C)

set(CMAKE_C_STANDARD 99)
set(CMAKE_C_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -Wall")


find_package(LIBSSH)

add_executable(ssh_honeypot main.c)
target_link_libraries(ssh_honeypot PUBLIC ssh)