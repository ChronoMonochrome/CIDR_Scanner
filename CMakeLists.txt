cmake_minimum_required(VERSION 3.10)
project(NetworkScannerTools C)

# Use C11 for atomic support and modern features
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

# Find necessary packages
find_package(Threads REQUIRED)

# 1. Bisect Ping Tool
add_executable(bisect_ping src/bisect_ping.c)
target_link_libraries(bisect_ping m Threads::Threads)

# 2. DNS Bisect Tool
add_executable(dns_bisect src/dns_bisect.c)
target_link_libraries(dns_bisect m Threads::Threads)

# 3. Mini Lookup Tool (Usually simple UDP/TCP, but linking threads for consistency)
add_executable(mini_lookup src/mini_lookup.c)
target_link_libraries(mini_lookup Threads::Threads)

# Compilation flags for better performance and debugging
target_compile_options(bisect_ping PRIVATE -Wall -O3)
target_compile_options(dns_bisect PRIVATE -Wall -O3)
target_compile_options(mini_lookup PRIVATE -Wall -O3)
