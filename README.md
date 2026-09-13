# Custom Network Packet Sniffer & Traffic Analyzer

A high-performance C++17 multi-threaded network packet analyzer built with `libpcap` and POSIX threads. Designed for real-time protocol analysis and statistical traffic inspection.

## Features
- **Raw Socket Capture**: Low-overhead packet interception using `libpcap`.
- **Multithreaded Processing**: Thread-safe producer-consumer model using condition variables.
- **Protocol Parsing**: Decodes Ethernet, IPv4, TCP, and UDP headers on-the-fly.
- **Traffic Analytics**: Aggregates throughput data, protocol distribution, and active host metrics.

## Architecture

[ Network Interface ] ---> ( NetworkSniffer )
|
[ ThreadSafeQueue ]
|
v
( PacketParser Worker )
|
( TrafficAnalyzer Engine )


## Quick Start (CMake)

### Prerequisites
- C++17 Compiler (GCC/Clang)
- CMake 3.16+
- `libpcap-dev`

#### Compile
```bash
mkdir build && cd build
cmake ..
make
sudo ./packet_analyzer eth0
```

#### Docker Setup

```bash
docker build -t packet-analyzer .
docker run --net=host --cap-add=NET_RAW packet-analyzer
```
