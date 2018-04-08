cmake_minimum_required (VERSION 2.6)
project (mptunnel)

set(CMAKE_BUILD_TYPE Release)

add_executable(mptunnel udp_server.c)

install (TARGETS mptunnel DESTINATION bin)

