#ifndef PACKET_H
#define PACKET_H

#include <stddef.h>
#include <stdint.h>

#define PACKET_HEADER_SIZE 10U
#define PACKET_MAX_PAYLOAD 1024U
#define PACKET_MAX_SIZE (PACKET_HEADER_SIZE + PACKET_MAX_PAYLOAD)

typedef enum {
  PACKET_DATA = 0,
  PACKET_ACK = 1,
  PACKET_FIN = 2
} packet_type;

typedef struct {
  packet_type type;
  uint32_t seq;
  uint16_t length;
  unsigned char payload[PACKET_MAX_PAYLOAD];
} transfer_packet;

uint16_t packet_checksum(const unsigned char *bytes, size_t length);
int packet_encode(const transfer_packet *packet, unsigned char *bytes,
                  size_t capacity, size_t *packet_size);
int packet_decode(const unsigned char *bytes, size_t packet_size,
                  transfer_packet *packet);

#endif
