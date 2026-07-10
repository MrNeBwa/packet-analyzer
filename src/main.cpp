#include "NetworkSniffer.hpp"
#include "PacketParser.hpp"
#include "ThreadSafeQueue.hpp"
#include "TrafficAnalyzer.hpp"
#include <iostream>
#include <thread>
#include <vector>

struct RawPacket {
  std::vector<uint8_t> data;
  uint32_t len;
};

int main(int argc, char *argv[]) {
  std::string interface = "eth0";
  if (argc > 1) {
    interface = argv[1];
  }

  std::cout << "[System] Starting Packet Analyzer on interface: "
            << interface << std::endl;

  ThreadSafeQueue<RawPacket> packet_queue;
  TrafficAnalyzer analyzer;
  std::atomic<bool> running{true};

  // Поток обработки пакетов из очереди
  std::thread worker_thread([&]() {
    while (running) {
      RawPacket raw;
      if (packet_queue.pop(raw)) {
        PacketInfo info;
        if (PacketParser::parse(raw.data.data(), raw.len, info)) {
          analyzer.process_packet(info);
        }
      }
    }
  });

  NetworkSniffer sniffer(interface);

  // Поток перехвата
  std::thread capture_thread([&]() {
    sniffer.start_capture(
        [&](const struct pcap_pkthdr *header, const u_char *packet) {
          RawPacket raw;
          raw.data.assign(packet, packet + header->caplen);
          raw.len = header->caplen;
          packet_queue.push(std::move(raw));
        });
  });

  std::cout << "[System] Press Enter to stop capture..." << std::endl;
  std::cin.get();

  sniffer.stop_capture();
  running = false;
  packet_queue.stop();

  if (capture_thread.joinable())
    capture_thread.join();
  if (worker_thread.joinable())
    worker_thread.join();

  analyzer.print_statistics();
  return 0;
}
