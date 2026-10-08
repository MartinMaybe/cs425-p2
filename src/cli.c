#include "cli.h"

#include <errno.h>
#include <getopt.h>
#include <limits.h>
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void print_usage(FILE *stream)
{
  fprintf(stream,
          "Usage: myapp send -s <session> [-w window] [-T timeout-ms] "
          "[-l loss]\n"
          "                  [-c corrupt] [-d dup] [-p port] <relay> <file>\n"
          "       myapp recv -s <session> [-p port] <relay> <file>\n"
          "\n"
          "  -s <session>     session name shared by the sender and the receiver\n"
          "  -w <window>      Go-Back-N window size in packets, 1 to 64 "
          "(default: 8)\n"
          "  -T <timeout-ms>  retransmission timeout in milliseconds "
          "(default: 250)\n"
          "  -l <loss>        probability the relay drops a packet (default: 0)\n"
          "  -c <corrupt>     probability the relay flips a bit (default: 0)\n"
          "  -d <dup>         probability the relay duplicates a packet "
          "(default: 0)\n"
          "  -p <port>        relay port (default: 4250)\n"
          "  <relay>          host name or address of the relay\n"
          "  <file>           file to send, or file to write what is received\n");
}

static void set_error(char *error, size_t error_size, const char *message)
{
  if (error != NULL && error_size > 0U) {
    (void)snprintf(error, error_size, "%s", message);
  }
}

static int parse_unsigned(const char *text, unsigned long maximum,
                          unsigned long *value)
{
  char *end = NULL;
  unsigned long parsed;

  if (text == NULL || text[0] == '\0' || text[0] == '-') {
    return 0;
  }

  errno = 0;
  parsed = strtoul(text, &end, 10);
  if (errno == ERANGE || end == text || *end != '\0' ||
      parsed > maximum) {
    return 0;
  }
  *value = parsed;
  return 1;
}

static int parse_probability(const char *text, double *value)
{
  char *end = NULL;
  double parsed;

  if (text == NULL || text[0] == '\0') {
    return 0;
  }

  errno = 0;
  parsed = strtod(text, &end);
  if (errno == ERANGE || end == text || *end != '\0' ||
      !isfinite(parsed) || parsed < 0.0 || parsed > 0.5) {
    return 0;
  }
  *value = parsed;
  return 1;
}

static int valid_session(const char *session)
{
  size_t length;
  size_t index;

  if (session == NULL) {
    return 0;
  }
  length = strlen(session);
  if (length < 1U || length > 32U) {
    return 0;
  }
  for (index = 0U; index < length; ++index) {
    if (!((session[index] >= 'a' && session[index] <= 'z') ||
          (session[index] >= '0' && session[index] <= '9') ||
          session[index] == '-')) {
      return 0;
    }
  }
  return 1;
}

static cli_parse_result invalid(char *error, size_t error_size,
                                const char *message)
{
  set_error(error, error_size, message);
  return CLI_PARSE_INVALID;
}

cli_parse_result parse_cli(int argc, char *argv[], cli_options *options,
                           char *error, size_t error_size)
{
  unsigned long value;
  int option;
  int option_argc;
  char **option_argv;
  char port_text[6];
  struct addrinfo hints;
  int address_result;

  if (options == NULL || argv == NULL || argc < 2) {
    return invalid(error, error_size, "Missing mode or arguments.");
  }

  memset(options, 0, sizeof(*options));
  options->window = 8U;
  options->timeout_ms = 250U;
  options->port = 4250U;
  options->loss = 0.0;
  options->corrupt = 0.0;
  options->duplicate = 0.0;

  if (strcmp(argv[1], "send") == 0) {
    options->mode = TRANSFER_SEND;
  } else if (strcmp(argv[1], "recv") == 0) {
    options->mode = TRANSFER_RECEIVE;
  } else {
    return invalid(error, error_size, "Mode must be 'send' or 'recv'.");
  }

  option_argc = argc - 1;
  option_argv = argv + 1;
  optind = 1;
  opterr = 0;
  while ((option = getopt(option_argc, option_argv, "s:w:T:l:c:d:p:")) != -1) {
    switch (option) {
    case 's':
      options->session = optarg;
      break;
    case 'w':
      if (options->mode != TRANSFER_SEND ||
          !parse_unsigned(optarg, 64UL, &value) || value < 1UL) {
        return invalid(error, error_size,
                       "Window size must be between 1 and 64 and is only "
                       "valid for send.");
      }
      options->window = (unsigned int)value;
      break;
    case 'T':
      if (options->mode != TRANSFER_SEND ||
          !parse_unsigned(optarg, (unsigned long)UINT_MAX, &value) ||
          value == 0UL) {
        return invalid(error, error_size,
                       "Timeout must be a positive integer and is only "
                       "valid for send.");
      }
      options->timeout_ms = (unsigned int)value;
      break;
    case 'l':
      if (options->mode != TRANSFER_SEND ||
          !parse_probability(optarg, &options->loss)) {
        return invalid(error, error_size,
                       "Loss probability must be from 0 to 0.5 and is only "
                       "valid for send.");
      }
      break;
    case 'c':
      if (options->mode != TRANSFER_SEND ||
          !parse_probability(optarg, &options->corrupt)) {
        return invalid(error, error_size,
                       "Corruption probability must be from 0 to 0.5 and is "
                       "only valid for send.");
      }
      break;
    case 'd':
      if (options->mode != TRANSFER_SEND ||
          !parse_probability(optarg, &options->duplicate)) {
        return invalid(error, error_size,
                       "Duplication probability must be from 0 to 0.5 and is "
                       "only valid for send.");
      }
      break;
    case 'p':
      if (!parse_unsigned(optarg, 65535UL, &value) || value == 0UL) {
        return invalid(error, error_size,
                       "Port must be an integer from 1 to 65535.");
      }
      options->port = (unsigned int)value;
      break;
    default:
      return invalid(error, error_size, "Unknown or incomplete option.");
    }
  }

  if (!valid_session(options->session)) {
    return invalid(error, error_size,
                   "Session must be 1 to 32 characters from a-z, 0-9, and -.");
  }
  if (option_argc - optind != 2) {
    return invalid(error, error_size,
                   "Exactly a relay host and a file path are required.");
  }
  options->relay = option_argv[optind];
  options->file = option_argv[optind + 1];

  (void)snprintf(port_text, sizeof(port_text), "%u", options->port);
  memset(&hints, 0, sizeof(hints));
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_DGRAM;
  hints.ai_flags = AI_NUMERICSERV;
  address_result = getaddrinfo(options->relay, port_text, &hints,
                               &options->relay_addresses);
  if (address_result != 0) {
    if (error != NULL && error_size > 0U) {
      (void)snprintf(error, error_size, "Cannot resolve relay '%s': %s",
                     options->relay, gai_strerror(address_result));
    }
    return CLI_PARSE_RESOLUTION_ERROR;
  }

  return CLI_PARSE_OK;
}

void free_cli_options(cli_options *options)
{
  if (options != NULL && options->relay_addresses != NULL) {
    freeaddrinfo(options->relay_addresses);
    options->relay_addresses = NULL;
  }
}
