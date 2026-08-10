#ifndef PACKET_PARSER_HPP
#define PACKET_PARSER_HPP

#include <cstdint>
#include <string>

enum class Protocol { TCP, UDP, UNKNOWN };

struct PacketInfo {
  std::string src_ip;
  std::string dst_ip;
  uint16_t src_port{0};
  uint16_t dst_port{0};
  Protocol protocol{Protocol::UNKNOWN};
  uint32_t payload_len{0};
  uint64_t timestamp_ms{0};
};

class PacketParser {
public:
  static bool parse(const uint8_t *packet_data, uint32_t packet_len,
                    PacketInfo &out_info);
};

#endif // PACKET_PARSER_HPP
