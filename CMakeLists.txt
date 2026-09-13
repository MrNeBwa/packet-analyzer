cmake_minimum_required(VERSION 3.16)
project(packet_analyzer VERSION 1.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -Wextra -O2")

# Поиск необходимых библиотек
find_package(PkgConfig REQUIRED)
pkg_check_modules(PCAP REQUIRED libpcap)

find_package(Threads REQUIRED)

include_directories(include ${PCAP_INCLUDE_DIRS})

set(SOURCES
    src/main.cpp
    src/NetworkSniffer.cpp
    src/PacketParser.cpp
    src/TrafficAnalyzer.cpp
)

add_executable(${PROJECT_NAME} ${SOURCES})

# Линовка библиотек
target_link_libraries(${PROJECT_NAME} PRIVATE ${PCAP_LIBRARIES} Threads::Threads)
