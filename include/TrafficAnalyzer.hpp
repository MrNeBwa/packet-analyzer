#ifndef TRAFFIC_ANALYZER_HPP
#define TRAFFIC_ANALYZER_HPP

#include "PacketParser.hpp"
#include <atomic>
#include <mutex>
#include <unordered_map>

class TrafficAnalyzer {
public:
  TrafficAnalyzer() = default;

  void process_packet(const PacketInfo &info);
  void print_statistics() const;

private:
  mutable std::mutex mutex_;
  std::atomic<uint64_t> total_packets_{0};
  std::atomic<uint64_t> total_bytes_{0};
  uint64_t tcp_packets_{0};
  uint64_t udp_packets_{0};
  std::unordered_map<std::string, uint64_t> ip_activity_map_;
};

#endif // TRAFFIC_ANALYZER_HPP
