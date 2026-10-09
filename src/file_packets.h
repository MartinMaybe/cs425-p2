#ifndef FILE_PACKETS_H
#define FILE_PACKETS_H

#include "packet.h"

#include <stddef.h>
#include <stdio.h>

typedef enum {
  FILE_PACKETS_OK,
  FILE_PACKETS_READ_ERROR,
  FILE_PACKETS_TOO_LARGE,
  FILE_PACKETS_NO_MEMORY
} file_packets_result;

file_packets_result file_packets_read(FILE *input, transfer_packet **packets,
                                      size_t *packet_count);

#endif
