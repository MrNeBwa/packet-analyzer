#include "NetworkSniffer.hpp"
#include <iostream>

NetworkSniffer::NetworkSniffer(std::string interface_name)
    : interface_name_(std::move(interface_name)), pcap_handle_(nullptr),
      capturing_(false) {}

NetworkSniffer::~NetworkSniffer() { stop_capture(); }

bool NetworkSniffer::start_capture(PacketHandler handler) {
  char errbuf[PCAP_ERRBUF_SIZE];

  // Открытие интерфейса для захвата трафика (promiscuous mode)
  pcap_handle_ =
      pcap_open_live(interface_name_.c_str(), BUFSIZ, 1, 1000, errbuf);
  if (!pcap_handle_) {
    std::cerr << "[Sniffer Error] Failed to open interface " << interface_name_
              << ": " << errbuf << std::endl;
    return false;
  }

  std::cout << "[Sniffer] Started capturing on interface: " << interface_name_
            << std::endl;
  capturing_.store(true);

  // Запуск бесконечного цикла чтения пакетов через libpcap
  auto *callback_arg = reinterpret_cast<u_char *>(&handler);
  pcap_loop(pcap_handle_, 0, NetworkSniffer::packet_callback, callback_arg);

  return true;
}

void NetworkSniffer::stop_capture() {
  if (capturing_.load()) {
    capturing_.store(false);
    if (pcap_handle_) {
      pcap_breakloop(pcap_handle_);
      pcap_close(pcap_handle_);
      pcap_handle_ = nullptr;
    }
    std::cout << "[Sniffer] Capture stopped." << std::endl;
  }
}

void NetworkSniffer::packet_callback(u_char *user_data,
                                     const struct pcap_pkthdr *pkthdr,
                                     const u_char *packet) {
  auto *handler = reinterpret_cast<PacketHandler *>(user_data);
  if (handler && *handler) {
    (*handler)(pkthdr, packet);
  }
}
