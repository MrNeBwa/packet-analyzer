#include "TrafficAnalyzer.hpp"
#include <iomanip>
#include <iostream>

void TrafficAnalyzer::process_packet(const PacketInfo &info) {
  total_packets_++;
  total_bytes_ += info.payload_len;

  std::lock_guard<std::mutex> lock(mutex_);
  if (info.protocol == Protocol::TCP) {
    tcp_packets_++;
  } else if (info.protocol == Protocol::UDP) {
    udp_packets_++;
  }

  ip_activity_map_[info.src_ip]++;
}

void TrafficAnalyzer::print_statistics() const {
  std::lock_guard<std::mutex> lock(mutex_);
  std::cout << "\n========== Traffic Analysis Stats ==========" << std::endl;
  std::cout << " Total Packets: " << total_packets_.load() << std::endl;
  std::cout << " Total Bytes:   " << total_bytes_.load() << " bytes"
            << std::endl;
  std::cout << " TCP Packets:   " << tcp_packets_ << std::endl;
  std::cout << " UDP Packets:   " << udp_packets_ << std::endl;
  std::cout << " Active IPs Count: " << ip_activity_map_.size() << std::endl;
  std::cout << "===========================================" << std::endl;
}
