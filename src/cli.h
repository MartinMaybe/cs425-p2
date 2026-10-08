#ifndef CLI_H
#define CLI_H

#include <stddef.h>
#include <stdio.h>
#include <netdb.h>

typedef enum {
  TRANSFER_SEND,
  TRANSFER_RECEIVE
} transfer_mode;

typedef struct {
  transfer_mode mode;
  const char *session;
  const char *relay;
  const char *file;
  unsigned int window;
  unsigned int timeout_ms;
  double loss;
  double corrupt;
  double duplicate;
  unsigned int port;
  struct addrinfo *relay_addresses;
} cli_options;

typedef enum {
  CLI_PARSE_OK,
  CLI_PARSE_INVALID,
  CLI_PARSE_RESOLUTION_ERROR
} cli_parse_result;

void print_usage(FILE *stream);
cli_parse_result parse_cli(int argc, char *argv[], cli_options *options,
                           char *error, size_t error_size);
void free_cli_options(cli_options *options);

#endif
