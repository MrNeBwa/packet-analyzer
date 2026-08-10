#include "PacketParser.hpp"
#include <arpa/inet.h>
#include <chrono>
#include <netinet/ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>

bool PacketParser::parse(const uint8_t *packet_data, uint32_t packet_len,
                         PacketInfo &out_info) {
  // Минимальный размер Ethernet-кадра (14 байт)
  if (packet_len < sizeof(struct ether_header)) {
    return false;
  }

  const auto *eth_header =
      reinterpret_cast<const struct ether_header *>(packet_data);
  if (ntohs(eth_header->ether_type) != ETHERTYPE_IP) {
    return false; // Игнорируем не-IP трафик для упрощения MVP
  }

  uint32_t ip_offset = sizeof(struct ether_header);
  if (packet_len < ip_offset + sizeof(struct iphdr)) {
    return false;
  }

  const auto *ip_header =
      reinterpret_cast<const struct iphdr *>(packet_data + ip_offset);

  char src_ip_str[INET_ADDRSTRLEN];
  char dst_ip_str[INET_ADDRSTRLEN];
  inet_ntop(AF_INET, &(ip_header->saddr), src_ip_str, INET_ADDRSTRLEN);
  inet_ntop(AF_INET, &(ip_header->daddr), dst_ip_str, INET_ADDRSTRLEN);

  out_info.src_ip = src_ip_str;
  out_info.dst_ip = dst_ip_str;

  uint32_t transport_offset = ip_offset + (ip_header->ihl * 4);

  if (ip_header->protocol == IPPROTO_TCP) {
    if (packet_len < transport_offset + sizeof(struct tcphdr))
      return false;
    const auto *tcp_header =
        reinterpret_cast<const struct tcphdr *>(packet_data + transport_offset);
    out_info.src_port = ntohs(tcp_header->source);
    out_info.dst_port = ntohs(tcp_header->dest);
    out_info.protocol = Protocol::TCP;
  } else if (ip_header->protocol == IPPROTO_UDP) {
    if (packet_len < transport_offset + sizeof(struct udphdr))
      return false;
    const auto *udp_header =
        reinterpret_cast<const struct udphdr *>(packet_data + transport_offset);
    out_info.src_port = ntohs(udp_header->source);
    out_info.dst_port = ntohs(udp_header->dest);
    out_info.protocol = Protocol::UDP;
  } else {
    out_info.protocol = Protocol::UNKNOWN;
  }

  out_info.payload_len = packet_len;
  out_info.timestamp_ms =
      std::chrono::duration_cast<std::chrono::milliseconds>(
          std::chrono::system_clock::now().time_since_epoch())
          .count();

  return true;
}
