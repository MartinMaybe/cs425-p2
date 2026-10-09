#include "file_packets.h"

#include <stdlib.h>
#include <string.h>

#define MAX_FILE_SIZE (16U * 1024U * 1024U)

file_packets_result file_packets_read(FILE *input, transfer_packet **packets,
                                      size_t *packet_count)
{
  size_t capacity = 0U;
  size_t total_bytes = 0U;

  if (packets == NULL || packet_count == NULL) {
    return FILE_PACKETS_READ_ERROR;
  }
  *packets = NULL;
  *packet_count = 0U;
  if (input == NULL) {
    return FILE_PACKETS_READ_ERROR;
  }

  for (;;) {
    transfer_packet packet;
    size_t count;

    memset(&packet, 0, sizeof(packet));
    packet.type = PACKET_DATA;
    count = fread(packet.payload, 1U, PACKET_MAX_PAYLOAD, input);
    if (count == 0U) {
      if (ferror(input)) {
        free(*packets);
        *packets = NULL;
        *packet_count = 0U;
        return FILE_PACKETS_READ_ERROR;
      }
      return FILE_PACKETS_OK;
    }
    if (count > (size_t)MAX_FILE_SIZE ||
        total_bytes > (size_t)MAX_FILE_SIZE - count) {
      free(*packets);
      *packets = NULL;
      *packet_count = 0U;
      return FILE_PACKETS_TOO_LARGE;
    }
    total_bytes += count;

    if (*packet_count == capacity) {
      size_t next_capacity = capacity == 0U ? 16U : capacity * 2U;
      transfer_packet *grown;
      size_t maximum_packets = (size_t)MAX_FILE_SIZE / PACKET_MAX_PAYLOAD;

      if (next_capacity > maximum_packets) {
        next_capacity = maximum_packets;
      }
      grown = realloc(*packets, next_capacity * sizeof(**packets));
      if (grown == NULL) {
        free(*packets);
        *packets = NULL;
        *packet_count = 0U;
        return FILE_PACKETS_NO_MEMORY;
      }
      *packets = grown;
      capacity = next_capacity;
    }

    packet.seq = (uint32_t)*packet_count;
    packet.length = (uint16_t)count;
    (*packets)[*packet_count] = packet;
    ++(*packet_count);
  }
}
