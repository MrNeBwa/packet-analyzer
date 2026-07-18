#ifndef NETWORK_SNIFFER_HPP
#define NETWORK_SNIFFER_HPP

#include <atomic>
#include <functional>
#include <memory>
#include <pcap.h>
#include <string>

using PacketHandler =
    std::function<void(const struct pcap_pkthdr *, const u_char *)>;

class NetworkSniffer {
public:
  explicit NetworkSniffer(std::string interface_name);
  ~NetworkSniffer();

  NetworkSniffer(const NetworkSniffer &) = delete;
  NetworkSniffer &operator=(const NetworkSniffer &) = delete;

  bool start_capture(PacketHandler handler);
  void stop_capture();

  bool is_capturing() const { return capturing_.load(); }

private:
  std::string interface_name_;
  pcap_t *pcap_handle_;
  std::atomic<bool> capturing_;

  static void packet_callback(u_char *user_data,
                              const struct pcap_pkthdr *pkthdr,
                              const u_char *packet);
};

#endif // NETWORK_SNIFFER_HPP
