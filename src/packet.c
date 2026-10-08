#include "packet.h"

#include <string.h>

static uint16_t read_u16(const unsigned char *bytes)
{
  return (uint16_t)(((uint16_t)bytes[0] << 8U) | (uint16_t)bytes[1]);
}

static uint32_t read_u32(const unsigned char *bytes)
{
  return ((uint32_t)bytes[0] << 24U) |
         ((uint32_t)bytes[1] << 16U) |
         ((uint32_t)bytes[2] << 8U) |
         (uint32_t)bytes[3];
}

static void write_u16(unsigned char *bytes, uint16_t value)
{
  bytes[0] = (unsigned char)(value >> 8U);
  bytes[1] = (unsigned char)(value & 0xffU);
}

static void write_u32(unsigned char *bytes, uint32_t value)
{
  bytes[0] = (unsigned char)(value >> 24U);
  bytes[1] = (unsigned char)((value >> 16U) & 0xffU);
  bytes[2] = (unsigned char)((value >> 8U) & 0xffU);
  bytes[3] = (unsigned char)(value & 0xffU);
}

uint16_t packet_checksum(const unsigned char *bytes, size_t length)
{
  uint32_t sum = 0U;
  size_t offset = 0U;

  while (offset + 1U < length) {
    sum += ((uint32_t)bytes[offset] << 8U) | (uint32_t)bytes[offset + 1U];
    offset += 2U;
  }
  if (offset < length) {
    sum += (uint32_t)bytes[offset] << 8U;
  }
  while ((sum >> 16U) != 0U) {
    sum = (sum & 0xffffU) + (sum >> 16U);
  }
  return (uint16_t)(~sum & 0xffffU);
}

int packet_encode(const transfer_packet *packet, unsigned char *bytes,
                  size_t capacity, size_t *packet_size)
{
  size_t size;
  uint16_t checksum;

  if (packet == NULL || bytes == NULL || packet_size == NULL ||
      (packet->type != PACKET_DATA && packet->type != PACKET_ACK &&
       packet->type != PACKET_FIN) ||
      packet->length > PACKET_MAX_PAYLOAD ||
      (packet->type != PACKET_DATA && packet->length != 0U)) {
    return 0;
  }

  size = PACKET_HEADER_SIZE + (size_t)packet->length;
  if (capacity < size) {
    return 0;
  }

  bytes[0] = (unsigned char)packet->type;
  bytes[1] = 0U;
  bytes[2] = 0U;
  bytes[3] = 0U;
  write_u32(bytes + 4U, packet->seq);
  write_u16(bytes + 8U, packet->length);
  if (packet->length > 0U) {
    memcpy(bytes + PACKET_HEADER_SIZE, packet->payload, packet->length);
  }
  checksum = packet_checksum(bytes, size);
  write_u16(bytes + 2U, checksum);
  *packet_size = size;
  return 1;
}

int packet_decode(const unsigned char *bytes, size_t packet_size,
                  transfer_packet *packet)
{
  uint16_t length;

  if (bytes == NULL || packet == NULL || packet_size < PACKET_HEADER_SIZE ||
      packet_size > PACKET_MAX_SIZE || bytes[0] > (unsigned char)PACKET_FIN ||
      bytes[1] != 0U) {
    return 0;
  }

  length = read_u16(bytes + 8U);
  if (length > PACKET_MAX_PAYLOAD ||
      PACKET_HEADER_SIZE + (size_t)length != packet_size) {
    return 0;
  }
  if (bytes[0] != (unsigned char)PACKET_DATA && length != 0U) {
    return 0;
  }

  if (packet_checksum(bytes, packet_size) != 0U) {
    return 0;
  }

  packet->type = (packet_type)bytes[0];
  packet->seq = read_u32(bytes + 4U);
  packet->length = length;
  if (length > 0U) {
    memcpy(packet->payload, bytes + PACKET_HEADER_SIZE, length);
  }
  return 1;
}
