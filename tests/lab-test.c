#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "harness/unity.h"
#include "../src/cli.h"
#include "../src/file_packets.h"
#include "../src/gbn.h"
#include "../src/lab.h"
#include "../src/packet.h"
#include "../src/transfer.h"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>


void setUp(void) {
  printf("Setting up tests...\n");
}

void tearDown(void) {
  printf("Tearing down tests...\n");
}

static int mock_relay_receive(int fd, unsigned char *bytes, size_t capacity,
                              struct sockaddr_in *client) {
  socklen_t client_size = (socklen_t)sizeof(*client);
  ssize_t received = recvfrom(fd, bytes, capacity, 0,
                              (struct sockaddr *)client, &client_size);
  return received < 0 ? -1 : (int)received;
}

static int mock_relay_send(int fd, const void *bytes, size_t size,
                           const struct sockaddr_in *client) {
  ssize_t sent = sendto(fd, bytes, size, 0, (const struct sockaddr *)client,
                        (socklen_t)sizeof(*client));
  return sent == (ssize_t)size;
}

static int mock_relay_send_packet(int fd, const transfer_packet *packet,
                                  const struct sockaddr_in *client) {
  unsigned char bytes[PACKET_MAX_SIZE];
  size_t size;
  return packet_encode(packet, bytes, sizeof(bytes), &size) &&
         mock_relay_send(fd, bytes, size, client);
}

static int mock_relay_receive_packet(int fd, transfer_packet *packet,
                                     struct sockaddr_in *client) {
  unsigned char bytes[PACKET_MAX_SIZE + 1U];
  int received = mock_relay_receive(fd, bytes, sizeof(bytes), client);
  return received >= 0 &&
         packet_decode(bytes, (size_t)received, packet);
}

static int mock_relay_run(int fd, int mode) {
  unsigned char hello[256];
  struct sockaddr_in client;
  transfer_packet packet;
  transfer_packet response;
  int sender_side = mode == 1 || mode == 3 || mode == 4 || mode == 5 ||
                    mode == 8 || mode == 9 || mode == 12;
  int received;
  int hello_count = 0;

  do {
    received = mock_relay_receive(fd, hello, sizeof(hello), &client);
    ++hello_count;
    if (received <= 0 || (size_t)received >= sizeof(hello)) {
      return 1;
    }
    hello[received] = '\0';
    if (mode != 6 && (mode != 7 || hello_count > 1)) {
      break;
    }
  } while (hello_count < 5);

  if (mode == 6) {
    sleep(6U);
    return 0;
  }
  if (mode == 2 || mode == 3) {
    return mock_relay_send(fd, "ERR refused by test relay", 25U, &client)
               ? 0
               : 2;
  }
  if (mode == 8) {
    return mock_relay_send(fd, "NOT OK", 6U, &client) ? 0 : 2;
  }
  if (mode == 7 && hello_count < 2) {
    return 3;
  }
  if (strncmp((char *)hello, "HELLO ", 6U) != 0 ||
      (mode != 6 &&
       !mock_relay_send(fd, "OK", 2U, &client))) {
    return 2;
  }
  if (mode == 5) {
    for (hello_count = 0; hello_count < 10; ++hello_count) {
      if (!mock_relay_receive_packet(fd, &packet, &client) ||
          packet.type != PACKET_DATA) {
        return 3;
      }
    }
    return 0;
  }
  if (mode == 6) {
    return 0;
  }
  if (mode == 13) {
    sleep(2U);
    return 0;
  }
  if (sender_side) {
    int data_copies = 0;
    do {
      if (!mock_relay_receive_packet(fd, &packet, &client) ||
          packet.type != PACKET_DATA || packet.seq != 0U ||
          packet.length != 3U ||
          memcmp(packet.payload, "abc", 3U) != 0) {
        return 3;
      }
      ++data_copies;
    } while (mode == 4 && data_copies == 1);
    memset(&response, 0, sizeof(response));
    response.type = PACKET_ACK;
    response.seq = 1U;
    if (mode == 9) {
      unsigned char damaged[PACKET_MAX_SIZE];
      size_t damaged_size;
      if (!packet_encode(&response, damaged, sizeof(damaged), &damaged_size)) {
        return 4;
      }
      damaged[damaged_size - 1U] ^= 0x01U;
      if (!mock_relay_send(fd, damaged, damaged_size, &client)) {
        return 4;
      }
    }
    if (!mock_relay_send_packet(fd, &response, &client) ||
        !mock_relay_receive_packet(fd, &packet, &client) ||
        packet.type != PACKET_FIN || packet.seq != 1U) {
      return 5;
    }
    response.seq = 2U;
    return mock_relay_send_packet(fd, &response, &client) ? 0 : 6;
  }

  if (mode == 10 &&
      !mock_relay_send(fd, "\x01\x02", 2U, &client)) {
    return 7;
  }
  memset(&packet, 0, sizeof(packet));
  packet.type = PACKET_DATA;
  packet.seq = 0U;
  packet.length = 3U;
  memcpy(packet.payload, "abc", 3U);
  if (!mock_relay_send_packet(fd, &packet, &client) ||
      !mock_relay_receive_packet(fd, &response, &client) ||
      response.type != PACKET_ACK || response.seq != 1U) {
    return 8;
  }
  packet.type = PACKET_FIN;
  packet.seq = 1U;
  packet.length = 0U;
  if (!mock_relay_send_packet(fd, &packet, &client) ||
      !mock_relay_receive_packet(fd, &response, &client) ||
      response.type != PACKET_ACK || response.seq != 2U ||
      !mock_relay_send_packet(fd, &packet, &client) ||
      !mock_relay_receive_packet(fd, &response, &client) ||
      response.type != PACKET_ACK || response.seq != 2U) {
    return 9;
  }
  if (mode == 0) {
    sleep(3U);
  }
  return 0;
}

static int start_mock_relay(int *socket_fd, pid_t *child, unsigned int *port,
                            int mode) {
  struct sockaddr_in address;
  socklen_t address_size = (socklen_t)sizeof(address);
  int fd = socket(AF_INET, SOCK_DGRAM, 0);
  if (fd < 0) {
    return 0;
  }
  memset(&address, 0, sizeof(address));
  address.sin_family = AF_INET;
  address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  address.sin_port = htons(0U);
  if (bind(fd, (struct sockaddr *)&address, sizeof(address)) != 0 ||
      getsockname(fd, (struct sockaddr *)&address, &address_size) != 0) {
    close(fd);
    return 0;
  }
  *port = (unsigned int)ntohs(address.sin_port);
  *child = fork();
  if (*child < 0) {
    close(fd);
    return 0;
  }
  if (*child == 0) {
    int result = mock_relay_run(fd, mode);
    close(fd);
    _exit(result);
  }
  *socket_fd = fd;
  return 1;
}

static int make_transfer_options(cli_options *options, const char *session,
                                 const char *path, unsigned int port) {
  char port_text[6];
  struct addrinfo hints;
  int result;

  memset(options, 0, sizeof(*options));
  options->mode = TRANSFER_SEND;
  options->session = session;
  options->file = path;
  options->window = 4U;
  options->timeout_ms = 500U;
  options->port = port;
  (void)snprintf(port_text, sizeof(port_text), "%u", port);
  memset(&hints, 0, sizeof(hints));
  hints.ai_family = AF_INET;
  hints.ai_socktype = SOCK_DGRAM;
  hints.ai_flags = AI_NUMERICSERV;
  result = getaddrinfo("127.0.0.1", port_text, &hints,
                       &options->relay_addresses);
  return result == 0;
}

static int write_test_file(const char *path, const unsigned char *bytes,
                           size_t size) {
  int fd = mkstemp((char *)path);
  size_t written = 0U;
  if (fd < 0) {
    return 0;
  }
  while (written < size) {
    ssize_t result = write(fd, bytes + written, size - written);
    if (result <= 0) {
      close(fd);
      return 0;
    }
    written += (size_t)result;
  }
  return close(fd) == 0;
}

static int finish_mock_relay(int socket_fd, pid_t child) {
  int status;
  close(socket_fd);
  if (waitpid(child, &status, 0) != child || !WIFEXITED(status)) {
    return 0;
  }
  return WEXITSTATUS(status) == 0;
}

void test_transfer_io_drives_state_machines_with_mock_relay(void) {
  char input_path[] = "/tmp/cs425-input-XXXXXX";
  char output_path[] = "/tmp/cs425-output-XXXXXX";
  static const unsigned char payload[] = "abc";
  cli_options options;
  struct addrinfo bad_address;
  FILE *output;
  unsigned char actual[sizeof(payload)];
  int socket_fd;
  int output_fd;
  unsigned int port;
  pid_t child;

  TEST_ASSERT_TRUE(write_test_file(input_path, payload, sizeof(payload) - 1U));
  output_fd = mkstemp(output_path);
  TEST_ASSERT_TRUE(output_fd >= 0);
  TEST_ASSERT_EQUAL_INT(0, close(output_fd));
  TEST_ASSERT_EQUAL_INT(0, unlink(output_path));

  TEST_ASSERT_TRUE(start_mock_relay(&socket_fd, &child, &port, 1));
  TEST_ASSERT_TRUE(make_transfer_options(&options, "sender-io", input_path,
                                         port));
  memset(&bad_address, 0, sizeof(bad_address));
  bad_address.ai_family = -1;
  bad_address.ai_socktype = SOCK_DGRAM;
  bad_address.ai_next = options.relay_addresses;
  options.relay_addresses = &bad_address;
  TEST_ASSERT_EQUAL_INT(0, send_transfer(&options));
  options.relay_addresses = bad_address.ai_next;
  free_cli_options(&options);
  TEST_ASSERT_TRUE(finish_mock_relay(socket_fd, child));

  TEST_ASSERT_TRUE(start_mock_relay(&socket_fd, &child, &port, 8));
  TEST_ASSERT_TRUE(make_transfer_options(&options, "unexpected-recv",
                                         output_path, port));
  options.mode = TRANSFER_RECEIVE;
  TEST_ASSERT_EQUAL_INT(2, receive_transfer(&options));
  free_cli_options(&options);
  TEST_ASSERT_TRUE(finish_mock_relay(socket_fd, child));

  TEST_ASSERT_TRUE(start_mock_relay(&socket_fd, &child, &port, 0));
  TEST_ASSERT_TRUE(make_transfer_options(&options, "receiver-io", output_path,
                                         port));
  options.mode = TRANSFER_RECEIVE;
  TEST_ASSERT_EQUAL_INT(0, receive_transfer(&options));
  free_cli_options(&options);
  TEST_ASSERT_TRUE(finish_mock_relay(socket_fd, child));

  output = fopen(output_path, "rb");
  TEST_ASSERT_NOT_NULL(output);
  TEST_ASSERT_EQUAL_INT(sizeof(payload) - 1U,
                        fread(actual, 1U, sizeof(actual), output));
  TEST_ASSERT_EQUAL_MEMORY(payload, actual, sizeof(actual));
  TEST_ASSERT_EQUAL_INT(0, fclose(output));
  TEST_ASSERT_EQUAL_INT(0, unlink(input_path));
  TEST_ASSERT_EQUAL_INT(0, unlink(output_path));
}

void test_transfer_io_registration_retries_and_failures(void) {
  char input_path[] = "/tmp/cs425-register-input-XXXXXX";
  char output_path[] = "/tmp/cs425-register-output-XXXXXX";
  static const unsigned char payload[] = "abc";
  cli_options options;
  int socket_fd;
  int output_fd;
  unsigned int port;
  pid_t child;

  TEST_ASSERT_TRUE(write_test_file(input_path, payload, sizeof(payload) - 1U));
  output_fd = mkstemp(output_path);
  TEST_ASSERT_TRUE(output_fd >= 0);
  TEST_ASSERT_EQUAL_INT(0, close(output_fd));
  TEST_ASSERT_EQUAL_INT(0, unlink(output_path));

  TEST_ASSERT_TRUE(start_mock_relay(&socket_fd, &child, &port, 12));
  TEST_ASSERT_TRUE(make_transfer_options(&options, "retry-io", input_path,
                                         port));
  TEST_ASSERT_EQUAL_INT(0, send_transfer(&options));
  free_cli_options(&options);
  TEST_ASSERT_TRUE(finish_mock_relay(socket_fd, child));

  TEST_ASSERT_TRUE(start_mock_relay(&socket_fd, &child, &port, 10));
  TEST_ASSERT_TRUE(make_transfer_options(&options, "invalid-datagram",
                                         output_path, port));
  options.mode = TRANSFER_RECEIVE;
  TEST_ASSERT_EQUAL_INT(0, receive_transfer(&options));
  free_cli_options(&options);
  TEST_ASSERT_TRUE(finish_mock_relay(socket_fd, child));

  TEST_ASSERT_TRUE(start_mock_relay(&socket_fd, &child, &port, 2));
  TEST_ASSERT_TRUE(make_transfer_options(&options, "refuse-recv", output_path,
                                         port));
  options.mode = TRANSFER_RECEIVE;
  TEST_ASSERT_EQUAL_INT(2, receive_transfer(&options));
  free_cli_options(&options);
  TEST_ASSERT_TRUE(finish_mock_relay(socket_fd, child));

  TEST_ASSERT_TRUE(start_mock_relay(&socket_fd, &child, &port, 3));
  TEST_ASSERT_TRUE(make_transfer_options(&options, "refuse-send", input_path,
                                         port));
  TEST_ASSERT_EQUAL_INT(2, send_transfer(&options));
  free_cli_options(&options);
  TEST_ASSERT_TRUE(finish_mock_relay(socket_fd, child));

  TEST_ASSERT_TRUE(start_mock_relay(&socket_fd, &child, &port, 8));
  TEST_ASSERT_TRUE(make_transfer_options(&options, "unexpected", input_path,
                                         port));
  TEST_ASSERT_EQUAL_INT(2, send_transfer(&options));
  free_cli_options(&options);
  TEST_ASSERT_TRUE(finish_mock_relay(socket_fd, child));

  TEST_ASSERT_TRUE(start_mock_relay(&socket_fd, &child, &port, 6));
  TEST_ASSERT_TRUE(make_transfer_options(&options, "no-reply", output_path,
                                         port));
  options.mode = TRANSFER_RECEIVE;
  TEST_ASSERT_EQUAL_INT(2, receive_transfer(&options));
  free_cli_options(&options);
  TEST_ASSERT_TRUE(finish_mock_relay(socket_fd, child));

  TEST_ASSERT_TRUE(start_mock_relay(&socket_fd, &child, &port, 13));
  TEST_ASSERT_TRUE(make_transfer_options(&options, "idle-timeout",
                                         output_path, port));
  options.mode = TRANSFER_RECEIVE;
  TEST_ASSERT_EQUAL_INT(2, receive_transfer(&options));
  free_cli_options(&options);
  TEST_ASSERT_TRUE(finish_mock_relay(socket_fd, child));

  TEST_ASSERT_TRUE(start_mock_relay(&socket_fd, &child, &port, 6));
  TEST_ASSERT_TRUE(make_transfer_options(&options, "no-sender-reply",
                                         input_path, port));
  TEST_ASSERT_EQUAL_INT(2, send_transfer(&options));
  free_cli_options(&options);
  TEST_ASSERT_TRUE(finish_mock_relay(socket_fd, child));

  TEST_ASSERT_EQUAL_INT(0, unlink(input_path));
  TEST_ASSERT_EQUAL_INT(0, unlink(output_path));
}

void test_transfer_io_sender_retransmission_corrupt_ack_and_timeout(void) {
  char input_path[] = "/tmp/cs425-retry-input-XXXXXX";
  static const unsigned char payload[] = "abc";
  cli_options options;
  int socket_fd;
  unsigned int port;
  pid_t child;

  TEST_ASSERT_TRUE(write_test_file(input_path, payload, sizeof(payload) - 1U));

  TEST_ASSERT_TRUE(start_mock_relay(&socket_fd, &child, &port, 4));
  TEST_ASSERT_TRUE(make_transfer_options(&options, "resend-data", input_path,
                                         port));
  options.timeout_ms = 50U;
  TEST_ASSERT_EQUAL_INT(0, send_transfer(&options));
  free_cli_options(&options);
  TEST_ASSERT_TRUE(finish_mock_relay(socket_fd, child));

  TEST_ASSERT_TRUE(start_mock_relay(&socket_fd, &child, &port, 9));
  TEST_ASSERT_TRUE(make_transfer_options(&options, "bad-ack", input_path,
                                         port));
  TEST_ASSERT_EQUAL_INT(0, send_transfer(&options));
  free_cli_options(&options);
  TEST_ASSERT_TRUE(finish_mock_relay(socket_fd, child));

  TEST_ASSERT_TRUE(start_mock_relay(&socket_fd, &child, &port, 5));
  TEST_ASSERT_TRUE(make_transfer_options(&options, "no-ack", input_path,
                                         port));
  options.timeout_ms = 5U;
  TEST_ASSERT_EQUAL_INT(2, send_transfer(&options));
  free_cli_options(&options);
  TEST_ASSERT_TRUE(finish_mock_relay(socket_fd, child));

  TEST_ASSERT_EQUAL_INT(0, unlink(input_path));
}

void test_transfer_io_input_and_socket_setup_failures(void) {
  char input_path[] = "/tmp/cs425-errors-input-XXXXXX";
  char output_path[] = "/tmp/cs425-errors-output-XXXXXX";
  char too_large_path[] = "/tmp/cs425-too-large-XXXXXX";
  char missing_path[] = "/tmp/cs425-missing-input-XXXXXX";
  char long_session[220];
  static const unsigned char payload[] = "abc";
  cli_options options;
  struct addrinfo bad_address;
  struct addrinfo *valid_addresses;
  struct sockaddr_in invalid_endpoint;
  int fd;
  int output_fd;

  TEST_ASSERT_TRUE(write_test_file(input_path, payload, sizeof(payload) - 1U));
  fd = mkstemp(missing_path);
  TEST_ASSERT_TRUE(fd >= 0);
  TEST_ASSERT_EQUAL_INT(0, close(fd));
  TEST_ASSERT_EQUAL_INT(0, unlink(missing_path));
  TEST_ASSERT_TRUE(make_transfer_options(&options, "missing-file", missing_path,
                                         4250U));
  TEST_ASSERT_EQUAL_INT(2, send_transfer(&options));
  free_cli_options(&options);

  TEST_ASSERT_TRUE(make_transfer_options(&options, "bad-window", input_path,
                                         4250U));
  options.window = 0U;
  TEST_ASSERT_EQUAL_INT(2, send_transfer(&options));
  free_cli_options(&options);

  TEST_ASSERT_TRUE(make_transfer_options(&options, "socket-failure", input_path,
                                         4250U));
  valid_addresses = options.relay_addresses;
  memset(&bad_address, 0, sizeof(bad_address));
  bad_address.ai_family = -1;
  bad_address.ai_socktype = SOCK_DGRAM;
  options.relay_addresses = &bad_address;
  TEST_ASSERT_EQUAL_INT(2, send_transfer(&options));
  options.relay_addresses = valid_addresses;
  free_cli_options(&options);

  TEST_ASSERT_TRUE(make_transfer_options(&options, "connect-failure",
                                         input_path, 4250U));
  valid_addresses = options.relay_addresses;
  memset(&bad_address, 0, sizeof(bad_address));
  memset(&invalid_endpoint, 0, sizeof(invalid_endpoint));
  invalid_endpoint.sin_family = AF_INET;
  bad_address.ai_family = AF_INET;
  bad_address.ai_socktype = SOCK_DGRAM;
  bad_address.ai_addr = (struct sockaddr *)&invalid_endpoint;
  bad_address.ai_addrlen = 0U;
  options.relay_addresses = &bad_address;
  TEST_ASSERT_EQUAL_INT(2, send_transfer(&options));
  options.relay_addresses = valid_addresses;
  free_cli_options(&options);

  TEST_ASSERT_TRUE(make_transfer_options(&options, "no-address", input_path,
                                         4250U));
  free_cli_options(&options);
  options.relay_addresses = NULL;
  TEST_ASSERT_EQUAL_INT(2, send_transfer(&options));

  TEST_ASSERT_TRUE(make_transfer_options(&options, "no-receiver-address",
                                         output_path, 4250U));
  free_cli_options(&options);
  options.mode = TRANSFER_RECEIVE;
  options.relay_addresses = NULL;
  TEST_ASSERT_EQUAL_INT(2, receive_transfer(&options));

  memset(&options, 0, sizeof(options));
  options.file = "/tmp/cs425-no-such-directory/output";
  TEST_ASSERT_EQUAL_INT(2, receive_transfer(&options));

  output_fd = mkstemp(output_path);
  TEST_ASSERT_TRUE(output_fd >= 0);
  TEST_ASSERT_EQUAL_INT(0, close(output_fd));
  TEST_ASSERT_EQUAL_INT(0, unlink(output_path));
  memset(long_session, 's', sizeof(long_session) - 1U);
  long_session[sizeof(long_session) - 1U] = '\0';
  TEST_ASSERT_TRUE(make_transfer_options(&options, long_session, output_path,
                                         4250U));
  options.mode = TRANSFER_RECEIVE;
  TEST_ASSERT_EQUAL_INT(2, receive_transfer(&options));
  free_cli_options(&options);

  memset(long_session, 's', sizeof(long_session) - 1U);
  long_session[sizeof(long_session) - 1U] = '\0';
  TEST_ASSERT_TRUE(make_transfer_options(&options, long_session, input_path,
                                         4250U));
  TEST_ASSERT_EQUAL_INT(2, send_transfer(&options));
  free_cli_options(&options);

  fd = mkstemp(too_large_path);
  TEST_ASSERT_TRUE(fd >= 0);
  TEST_ASSERT_EQUAL_INT(0, ftruncate(fd, (off_t)(16U * 1024U * 1024U + 1U)));
  TEST_ASSERT_EQUAL_INT(0, close(fd));
  TEST_ASSERT_TRUE(make_transfer_options(&options, "large-file", too_large_path,
                                         4250U));
  TEST_ASSERT_EQUAL_INT(2, send_transfer(&options));
  free_cli_options(&options);

  TEST_ASSERT_EQUAL_INT(0, unlink(input_path));
  TEST_ASSERT_EQUAL_INT(0, unlink(too_large_path));
  TEST_ASSERT_EQUAL_INT(0, unlink(output_path));
}

void test_get_greeting(void) {
  char *greeting = get_greeting("Alice");
  TEST_ASSERT_NOT_NULL(greeting);
  TEST_ASSERT_EQUAL_STRING("Hello, Alice!", greeting);
  free(greeting); // Free the allocated memory for the greeting

  greeting = get_greeting(NULL);
  TEST_ASSERT_NULL(greeting);

  greeting = get_greeting("");
  TEST_ASSERT_NOT_NULL(greeting);
  TEST_ASSERT_EQUAL_STRING("Hello, !", greeting);
  free(greeting);
}

void test_parse_send_arguments(void) {
  char *argv[] = {
    "myapp", "send", "-s", "session", "-w", "16", "-T", "100",
    "-l", "0.1", "-c", "0.2", "-d", "0.5", "-p", "4250",
    "127.0.0.1", "input.bin"
  };
  cli_options options;
  char error[256];

  TEST_ASSERT_EQUAL_INT(CLI_PARSE_OK,
                       parse_cli((int)(sizeof(argv) / sizeof(argv[0])), argv,
                                 &options, error, sizeof(error)));
  TEST_ASSERT_EQUAL_INT(TRANSFER_SEND, options.mode);
  TEST_ASSERT_EQUAL_STRING("session", options.session);
  TEST_ASSERT_EQUAL_STRING("127.0.0.1", options.relay);
  TEST_ASSERT_EQUAL_STRING("input.bin", options.file);
  TEST_ASSERT_EQUAL_INT(16, options.window);
  TEST_ASSERT_EQUAL_INT(100, options.timeout_ms);
  TEST_ASSERT_EQUAL_FLOAT(0.1, options.loss);
  TEST_ASSERT_EQUAL_FLOAT(0.2, options.corrupt);
  TEST_ASSERT_EQUAL_FLOAT(0.5, options.duplicate);
  TEST_ASSERT_EQUAL_INT(4250, options.port);
  free_cli_options(&options);
}

void test_parse_rejects_invalid_arguments(void) {
  char *argv[] = {
    "myapp", "recv", "-s", "session", "-w", "8", "127.0.0.1", "output.bin"
  };
  cli_options options;
  char error[256];

  TEST_ASSERT_EQUAL_INT(CLI_PARSE_INVALID,
                       parse_cli((int)(sizeof(argv) / sizeof(argv[0])), argv,
                                 &options, error, sizeof(error)));
}

void test_parse_rejects_invalid_session_and_probabilities(void) {
  char *bad_session[] = {
    "myapp", "recv", "-s", "Bad_Name", "127.0.0.1", "output.bin"
  };
  char *bad_probability[] = {
    "myapp", "send", "-s", "session", "-l", "0.51",
    "127.0.0.1", "input.bin"
  };
  cli_options options;
  char error[256];

  TEST_ASSERT_EQUAL_INT(CLI_PARSE_INVALID,
                       parse_cli((int)(sizeof(bad_session) /
                                       sizeof(bad_session[0])),
                                 bad_session, &options, error, sizeof(error)));
  TEST_ASSERT_EQUAL_INT(
      CLI_PARSE_INVALID,
      parse_cli((int)(sizeof(bad_probability) / sizeof(bad_probability[0])),
                bad_probability, &options, error, sizeof(error)));
}

void test_cli_usage_and_invalid_input_paths(void) {
  cli_options options;
  char error[256];
  char *unknown_mode[] = {"myapp", "other"};
  char *unknown_option[] = {
    "myapp", "send", "-s", "session", "-x", "127.0.0.1", "file"
  };
  char *missing_value[] = {"myapp", "send", "-s"};
  char *bad_window[] = {
    "myapp", "send", "-s", "session", "-w", "0", "localhost", "file"
  };
  char *empty_window[] = {
    "myapp", "send", "-s", "session", "-w", "", "localhost", "file"
  };
  char *negative_window[] = {
    "myapp", "send", "-s", "session", "-w", "-1", "localhost", "file"
  };
  char *bad_timeout[] = {
    "myapp", "send", "-s", "session", "-T", "0", "localhost", "file"
  };
  char *bad_loss[] = {
    "myapp", "send", "-s", "session", "-l", "nan", "localhost", "file"
  };
  char *empty_loss[] = {
    "myapp", "send", "-s", "session", "-l", "", "localhost", "file"
  };
  char *bad_corrupt[] = {
    "myapp", "send", "-s", "session", "-c", "-0.1", "localhost", "file"
  };
  char *bad_dup[] = {
    "myapp", "send", "-s", "session", "-d", "0.6", "localhost", "file"
  };
  char *bad_port[] = {
    "myapp", "recv", "-s", "session", "-p", "65536", "localhost", "file"
  };
  char *extra_arg[] = {
    "myapp", "recv", "-s", "session", "localhost", "file", "extra"
  };
  char *unresolvable[] = {
    "myapp", "recv", "-s", "session", "invalid-host.invalid", "file"
  };
  char *valid_recv[] = {
    "myapp", "recv", "-s", "session", "localhost", "file"
  };
  char *missing_session[] = {"myapp", "recv", "localhost", "file"};
  char *valid_prefix[] = {"myapp", "recv"};
  FILE *usage;

  usage = tmpfile();
  TEST_ASSERT_NOT_NULL(usage);
  print_usage(usage);
  TEST_ASSERT_TRUE(ftell(usage) > 0L);
  TEST_ASSERT_EQUAL_INT(0, fclose(usage));
  TEST_ASSERT_EQUAL_INT(CLI_PARSE_INVALID,
                       parse_cli(1, unknown_mode, &options, error, sizeof(error)));
  TEST_ASSERT_EQUAL_INT(CLI_PARSE_INVALID,
                       parse_cli(2, unknown_mode, &options, error, sizeof(error)));
  TEST_ASSERT_EQUAL_INT(CLI_PARSE_INVALID,
                       parse_cli(2, unknown_mode, NULL, error, sizeof(error)));
  TEST_ASSERT_EQUAL_INT(CLI_PARSE_INVALID,
                       parse_cli(2, valid_prefix, NULL, error, sizeof(error)));
  TEST_ASSERT_EQUAL_INT(CLI_PARSE_INVALID,
                       parse_cli(3, NULL, &options, error, sizeof(error)));
  TEST_ASSERT_EQUAL_INT(CLI_PARSE_INVALID,
                       parse_cli(0, unknown_mode, &options, error, sizeof(error)));
  TEST_ASSERT_EQUAL_INT(CLI_PARSE_INVALID,
                       parse_cli(7, unknown_option, &options, error, sizeof(error)));
  TEST_ASSERT_EQUAL_INT(CLI_PARSE_INVALID,
                       parse_cli(3, missing_value, &options, error, sizeof(error)));
  TEST_ASSERT_EQUAL_INT(CLI_PARSE_INVALID,
                       parse_cli(8, bad_window, &options, error, sizeof(error)));
  TEST_ASSERT_EQUAL_INT(CLI_PARSE_INVALID,
                       parse_cli(8, empty_window, &options, error, sizeof(error)));
  TEST_ASSERT_EQUAL_INT(CLI_PARSE_INVALID,
                       parse_cli(8, negative_window, &options, error,
                                 sizeof(error)));
  TEST_ASSERT_EQUAL_INT(CLI_PARSE_INVALID,
                       parse_cli(8, bad_timeout, &options, error, sizeof(error)));
  TEST_ASSERT_EQUAL_INT(CLI_PARSE_INVALID,
                       parse_cli(8, bad_loss, &options, error, sizeof(error)));
  TEST_ASSERT_EQUAL_INT(CLI_PARSE_INVALID,
                       parse_cli(8, empty_loss, &options, error, sizeof(error)));
  TEST_ASSERT_EQUAL_INT(CLI_PARSE_INVALID,
                       parse_cli(8, bad_corrupt, &options, error, sizeof(error)));
  TEST_ASSERT_EQUAL_INT(CLI_PARSE_INVALID,
                       parse_cli(8, bad_dup, &options, error, sizeof(error)));
  TEST_ASSERT_EQUAL_INT(CLI_PARSE_INVALID,
                       parse_cli(8, bad_port, &options, error, sizeof(error)));
  TEST_ASSERT_EQUAL_INT(CLI_PARSE_INVALID,
                       parse_cli(7, extra_arg, &options, error, sizeof(error)));
  TEST_ASSERT_EQUAL_INT(CLI_PARSE_INVALID,
                       parse_cli(4, missing_session, &options, error,
                                 sizeof(error)));
  TEST_ASSERT_EQUAL_INT(CLI_PARSE_RESOLUTION_ERROR,
                       parse_cli(6, unresolvable, &options, error,
                                 sizeof(error)));
  TEST_ASSERT_EQUAL_INT(CLI_PARSE_OK,
                       parse_cli(6, valid_recv, &options, error, sizeof(error)));
  free_cli_options(&options);
  free_cli_options(NULL);
}

void test_packet_checksum_example(void) {
  const unsigned char example[] = {
    0x00, 0x01, 0xf2, 0x03, 0xf4, 0xf5, 0xf6, 0xf7
  };

  TEST_ASSERT_EQUAL_HEX16(0x220d, packet_checksum(example, sizeof(example)));
}

void test_packet_checksum_odd_length(void) {
  const unsigned char odd_packet[] = {0x00, 0x01, 0xf2};

  TEST_ASSERT_EQUAL_HEX16(0x0dfe,
                          packet_checksum(odd_packet, sizeof(odd_packet)));
}

void test_packet_encode_decode(void) {
  transfer_packet original;
  transfer_packet decoded;
  unsigned char bytes[PACKET_MAX_SIZE];
  size_t packet_size = 0U;

  memset(&original, 0, sizeof(original));
  original.type = PACKET_DATA;
  original.seq = 0x01020304U;
  original.length = 3U;
  original.payload[0] = 'a';
  original.payload[1] = 'b';
  original.payload[2] = 'c';
  TEST_ASSERT_TRUE(packet_encode(&original, bytes, sizeof(bytes), &packet_size));
  TEST_ASSERT_EQUAL_INT(13, packet_size);
  TEST_ASSERT_TRUE(packet_decode(bytes, packet_size, &decoded));
  TEST_ASSERT_EQUAL_INT(PACKET_DATA, decoded.type);
  TEST_ASSERT_EQUAL_UINT32(original.seq, decoded.seq);
  TEST_ASSERT_EQUAL_INT(3, decoded.length);
  TEST_ASSERT_EQUAL_MEMORY(original.payload, decoded.payload, 3);

  bytes[12] ^= 0x01U;
  TEST_ASSERT_FALSE(packet_decode(bytes, packet_size, &decoded));
}

void test_packet_wire_bytes_match_protocol_example(void) {
  static const unsigned char data_expected[] = {
    0x00, 0x00, 0x96, 0x91, 0x00, 0x00, 0x00, 0x02,
    0x00, 0x03, 0x48, 0x69, 0x21
  };
  static const unsigned char ack_expected[] = {
    0x01, 0x00, 0xfe, 0xfc, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00
  };
  transfer_packet packet;
  unsigned char bytes[PACKET_MAX_SIZE];
  size_t size;

  memset(&packet, 0, sizeof(packet));
  packet.type = PACKET_DATA;
  packet.seq = 2U;
  packet.length = 3U;
  memcpy(packet.payload, "Hi!", 3U);
  TEST_ASSERT_TRUE(packet_encode(&packet, bytes, sizeof(bytes), &size));
  TEST_ASSERT_EQUAL_INT(sizeof(data_expected), size);
  TEST_ASSERT_EQUAL_MEMORY(data_expected, bytes, sizeof(data_expected));

  memset(&packet, 0, sizeof(packet));
  packet.type = PACKET_ACK;
  packet.seq = 3U;
  TEST_ASSERT_TRUE(packet_encode(&packet, bytes, sizeof(bytes), &size));
  TEST_ASSERT_EQUAL_INT(sizeof(ack_expected), size);
  TEST_ASSERT_EQUAL_MEMORY(ack_expected, bytes, sizeof(ack_expected));
}

static void set_wire_checksum(unsigned char *bytes, size_t size) {
  uint16_t checksum;
  bytes[2] = 0U;
  bytes[3] = 0U;
  checksum = packet_checksum(bytes, size);
  bytes[2] = (unsigned char)(checksum >> 8U);
  bytes[3] = (unsigned char)(checksum & 0xffU);
}

void test_packet_decoder_rejects_malformed_datagrams(void) {
  transfer_packet packet;
  transfer_packet decoded;
  unsigned char bytes[PACKET_MAX_SIZE];
  size_t size;

  memset(&packet, 0, sizeof(packet));
  packet.type = PACKET_DATA;
  packet.length = 3U;
  memcpy(packet.payload, "abc", 3U);
  TEST_ASSERT_TRUE(packet_encode(&packet, bytes, sizeof(bytes), &size));
  TEST_ASSERT_FALSE(packet_decode(bytes, PACKET_HEADER_SIZE - 1U, &decoded));

  TEST_ASSERT_FALSE(packet_decode(bytes, size - 1U, &decoded));

  bytes[0] = 3U;
  set_wire_checksum(bytes, size);
  TEST_ASSERT_FALSE(packet_decode(bytes, size, &decoded));

  bytes[0] = PACKET_DATA;
  bytes[8] = 0U;
  bytes[9] = 4U;
  set_wire_checksum(bytes, size);
  TEST_ASSERT_FALSE(packet_decode(bytes, size, &decoded));

  bytes[0] = PACKET_DATA;
  set_wire_checksum(bytes, size);
  bytes[PACKET_HEADER_SIZE + 1U] ^= 0x01U;
  TEST_ASSERT_FALSE(packet_decode(bytes, size, &decoded));
}

void test_packet_encoder_rejects_invalid_inputs(void) {
  transfer_packet packet;
  unsigned char bytes[PACKET_MAX_SIZE];
  size_t size = 0U;

  memset(&packet, 0, sizeof(packet));
  packet.type = PACKET_ACK;
  TEST_ASSERT_FALSE(packet_encode(NULL, bytes, sizeof(bytes), &size));
  TEST_ASSERT_FALSE(packet_encode(&packet, NULL, sizeof(bytes), &size));
  TEST_ASSERT_FALSE(packet_encode(&packet, bytes, sizeof(bytes), NULL));
  TEST_ASSERT_FALSE(packet_encode(&packet, bytes, PACKET_HEADER_SIZE - 1U,
                                  &size));
  packet.type = (packet_type)3;
  TEST_ASSERT_FALSE(packet_encode(&packet, bytes, sizeof(bytes), &size));
  packet.type = PACKET_ACK;
  packet.length = 1U;
  TEST_ASSERT_FALSE(packet_encode(&packet, bytes, sizeof(bytes), &size));
  packet.type = PACKET_DATA;
  packet.length = PACKET_MAX_PAYLOAD + 1U;
  TEST_ASSERT_FALSE(packet_encode(&packet, bytes, sizeof(bytes), &size));
}

void test_packet_decoder_rejects_invalid_header_fields(void) {
  transfer_packet packet;
  transfer_packet decoded;
  unsigned char bytes[PACKET_MAX_SIZE];
  size_t size;

  memset(&packet, 0, sizeof(packet));
  packet.type = PACKET_ACK;
  TEST_ASSERT_TRUE(packet_encode(&packet, bytes, sizeof(bytes), &size));
  TEST_ASSERT_FALSE(packet_decode(NULL, size, &decoded));
  TEST_ASSERT_FALSE(packet_decode(bytes, size, NULL));
  TEST_ASSERT_FALSE(packet_decode(bytes, PACKET_MAX_SIZE + 1U, &decoded));

  bytes[1] = 1U;
  set_wire_checksum(bytes, size);
  TEST_ASSERT_FALSE(packet_decode(bytes, size, &decoded));
  bytes[1] = 0U;
  bytes[8] = 0x04U;
  bytes[9] = 0x01U;
  set_wire_checksum(bytes, size);
  TEST_ASSERT_FALSE(packet_decode(bytes, size, &decoded));

  bytes[8] = 0U;
  bytes[9] = 0U;
  bytes[0] = PACKET_ACK;
  set_wire_checksum(bytes, size);
  TEST_ASSERT_TRUE(packet_decode(bytes, size, &decoded));

  memset(&packet, 0, sizeof(packet));
  packet.type = PACKET_DATA;
  packet.length = 1U;
  packet.payload[0] = 'x';
  TEST_ASSERT_TRUE(packet_encode(&packet, bytes, sizeof(bytes), &size));
  bytes[0] = PACKET_ACK;
  set_wire_checksum(bytes, size);
  TEST_ASSERT_FALSE(packet_decode(bytes, size, &decoded));
}

static void make_data_packets(transfer_packet *packets, uint32_t count) {
  uint32_t index;
  for (index = 0U; index < count; ++index) {
    memset(&packets[index], 0, sizeof(packets[index]));
    packets[index].type = PACKET_DATA;
    packets[index].seq = index;
    packets[index].length = 1U;
    packets[index].payload[0] = (unsigned char)('a' + index);
  }
}

#define TEST_CHANNEL_CAPACITY 4096U

typedef struct {
  unsigned char bytes[PACKET_MAX_SIZE];
  size_t size;
} test_datagram;

typedef struct {
  test_datagram *datagrams;
  size_t count;
  size_t capacity;
  unsigned int dropped;
  unsigned int corrupted;
  unsigned int duplicated;
} test_channel;

static uint32_t test_random_next(uint32_t *state) {
  uint32_t value = *state;
  value ^= value << 13U;
  value ^= value >> 17U;
  value ^= value << 5U;
  *state = value;
  return value;
}

static int test_channel_push(test_channel *channel,
                             const unsigned char *bytes, size_t size) {
  test_datagram *datagram;
  if (channel->count >= channel->capacity || size > PACKET_MAX_SIZE) {
    return 0;
  }
  datagram = &channel->datagrams[channel->count++];
  memcpy(datagram->bytes, bytes, size);
  datagram->size = size;
  return 1;
}

static int test_channel_send(test_channel *channel,
                             const transfer_packet *packet,
                             uint32_t *random_state) {
  unsigned char bytes[PACKET_MAX_SIZE];
  size_t size;
  uint32_t damage;

  if (!packet_encode(packet, bytes, sizeof(bytes), &size)) {
    return 0;
  }
  damage = test_random_next(random_state) % 100U;
  if (damage < 20U) {
    ++channel->dropped;
    return 1;
  }
  if (damage < 40U) {
    uint32_t bit = test_random_next(random_state) % (uint32_t)(size * 8U);
    bytes[bit / 8U] ^= (unsigned char)(1U << (bit % 8U));
    ++channel->corrupted;
    return test_channel_push(channel, bytes, size);
  }
  if (damage < 60U) {
    ++channel->duplicated;
    return test_channel_push(channel, bytes, size) &&
           test_channel_push(channel, bytes, size);
  }
  return test_channel_push(channel, bytes, size);
}

static int test_emit_actions(test_channel *channel,
                             const gbn_actions *actions,
                             uint32_t *random_state) {
  size_t index;
  for (index = 0U; index < actions->packet_count; ++index) {
    if (!test_channel_send(channel, &actions->packets[index], random_state)) {
      return 0;
    }
  }
  return 1;
}

static int run_damaged_state_machine_transfer(uint32_t seed,
                                              unsigned int *damage_flags) {
  const size_t source_size = 7001U;
  const uint32_t packet_count =
      (uint32_t)((source_size + PACKET_MAX_PAYLOAD - 1U) /
                 PACKET_MAX_PAYLOAD);
  unsigned char *source = malloc(source_size);
  unsigned char *delivered = malloc(source_size);
  transfer_packet *packets =
      calloc(packet_count, sizeof(*packets));
  test_channel data_channel = {0};
  test_channel ack_channel = {0};
  gbn_sender sender;
  gbn_receiver receiver;
  gbn_actions actions;
  uint32_t random_state = seed;
  uint32_t index;
  size_t data_read = 0U;
  size_t ack_read = 0U;
  size_t delivered_size = 0U;
  int64_t now = 0;
  unsigned int steps = 0U;
  int success = 0;

  data_channel.capacity = TEST_CHANNEL_CAPACITY;
  ack_channel.capacity = TEST_CHANNEL_CAPACITY;
  data_channel.datagrams = calloc(data_channel.capacity,
                                  sizeof(*data_channel.datagrams));
  ack_channel.datagrams = calloc(ack_channel.capacity,
                                 sizeof(*ack_channel.datagrams));
  if (source == NULL || delivered == NULL || packets == NULL ||
      data_channel.datagrams == NULL || ack_channel.datagrams == NULL) {
    goto cleanup;
  }

  for (index = 0U; index < source_size; ++index) {
    source[index] = (unsigned char)((index * 37U + index / 11U) & 0xffU);
  }
  for (index = 0U; index < packet_count; ++index) {
    size_t offset = (size_t)index * PACKET_MAX_PAYLOAD;
    size_t remaining = source_size - offset;
    size_t length = remaining < PACKET_MAX_PAYLOAD
                        ? remaining
                        : PACKET_MAX_PAYLOAD;
    packets[index].type = PACKET_DATA;
    packets[index].seq = index;
    packets[index].length = (uint16_t)length;
    memcpy(packets[index].payload, source + offset, length);
  }

  if (!gbn_sender_init(&sender, packets, packet_count, 5U, 40) ) {
    goto cleanup;
  }
  gbn_receiver_init(&receiver, now);
  gbn_sender_start(&sender, now, &actions);
  if (!test_emit_actions(&data_channel, &actions, &random_state)) {
    goto cleanup;
  }

  while (!sender.completed && !sender.failed && steps < 100000U) {
    ++steps;
    if (data_read < data_channel.count) {
      test_datagram datagram = data_channel.datagrams[data_read++];
      transfer_packet packet;
      if (packet_decode(datagram.bytes, datagram.size, &packet)) {
        gbn_receiver_on_packet(&receiver, &packet, now, &actions);
        if (actions.deliver_payload) {
          if (delivered_size + actions.payload_length > source_size) {
            goto cleanup;
          }
          memcpy(delivered + delivered_size, actions.payload,
                 actions.payload_length);
          delivered_size += actions.payload_length;
        }
        if (!test_emit_actions(&ack_channel, &actions, &random_state)) {
          goto cleanup;
        }
      }
      continue;
    }

    if (ack_read < ack_channel.count) {
      test_datagram datagram = ack_channel.datagrams[ack_read++];
      transfer_packet ack;
      if (packet_decode(datagram.bytes, datagram.size, &ack) &&
          ack.type == PACKET_ACK) {
        gbn_sender_on_ack(&sender, &ack, now, &actions);
        if (!test_emit_actions(&data_channel, &actions, &random_state)) {
          goto cleanup;
        }
      }
      continue;
    }

    if (!sender.timer_running) {
      goto cleanup;
    }
    now = sender.timer_deadline_ms;
    gbn_sender_on_timeout(&sender, now, &actions);
    if (actions.failed ||
        !test_emit_actions(&data_channel, &actions, &random_state)) {
      goto cleanup;
    }
  }

  success = sender.completed && !sender.failed &&
            delivered_size == source_size &&
            memcmp(source, delivered, source_size) == 0;

cleanup:
  if (damage_flags != NULL) {
    if (data_channel.dropped > 0U) {
      *damage_flags |= 1U << 0U;
    }
    if (data_channel.corrupted > 0U) {
      *damage_flags |= 1U << 1U;
    }
    if (data_channel.duplicated > 0U) {
      *damage_flags |= 1U << 2U;
    }
    if (ack_channel.dropped > 0U) {
      *damage_flags |= 1U << 3U;
    }
    if (ack_channel.corrupted > 0U) {
      *damage_flags |= 1U << 4U;
    }
    if (ack_channel.duplicated > 0U) {
      *damage_flags |= 1U << 5U;
    }
  }
  free(source);
  free(delivered);
  free(packets);
  free(data_channel.datagrams);
  free(ack_channel.datagrams);
  return success;
}

void test_sender_window_cumulative_ack_and_fin(void) {
  transfer_packet data[5];
  transfer_packet ack;
  gbn_sender sender;
  gbn_actions actions;

  make_data_packets(data, 5U);
  TEST_ASSERT_TRUE(gbn_sender_init(&sender, data, 5U, 3U, 100));
  gbn_sender_start(&sender, 0, &actions);
  TEST_ASSERT_EQUAL_INT(3, actions.packet_count);
  TEST_ASSERT_EQUAL_UINT32(0U, actions.packets[0].seq);
  TEST_ASSERT_EQUAL_UINT32(2U, actions.packets[2].seq);
  TEST_ASSERT_EQUAL_INT(1, actions.timer_running);
  TEST_ASSERT_EQUAL_INT64(100, actions.timer_deadline_ms);

  memset(&ack, 0, sizeof(ack));
  ack.type = PACKET_ACK;
  ack.seq = 0U;
  gbn_sender_on_ack(&sender, &ack, 25, &actions);
  TEST_ASSERT_EQUAL_UINT32(0U, sender.base);
  TEST_ASSERT_EQUAL_INT(0, actions.packet_count);
  TEST_ASSERT_EQUAL_INT64(100, actions.timer_deadline_ms);

  ack.seq = 2U;
  gbn_sender_on_ack(&sender, &ack, 50, &actions);
  TEST_ASSERT_EQUAL_INT(2, actions.packet_count);
  TEST_ASSERT_EQUAL_UINT32(3U, actions.packets[0].seq);
  TEST_ASSERT_EQUAL_UINT32(4U, actions.packets[1].seq);
  TEST_ASSERT_EQUAL_INT64(150, actions.timer_deadline_ms);

  ack.seq = 5U;
  gbn_sender_on_ack(&sender, &ack, 60, &actions);
  TEST_ASSERT_EQUAL_INT(1, actions.packet_count);
  TEST_ASSERT_EQUAL_INT(PACKET_FIN, actions.packets[0].type);
  TEST_ASSERT_EQUAL_UINT32(5U, actions.packets[0].seq);
  TEST_ASSERT_EQUAL_INT64(160, actions.timer_deadline_ms);

  ack.seq = 6U;
  gbn_sender_on_ack(&sender, &ack, 70, &actions);
  TEST_ASSERT_TRUE(sender.completed);
  TEST_ASSERT_TRUE(actions.completed);
  TEST_ASSERT_FALSE(actions.timer_running);
}

void test_sender_timeout_retransmits_and_gives_up(void) {
  transfer_packet data[2];
  gbn_sender sender;
  gbn_actions actions;
  int timeout;

  make_data_packets(data, 2U);
  TEST_ASSERT_TRUE(gbn_sender_init(&sender, data, 2U, 2U, 25));
  gbn_sender_start(&sender, 100, &actions);
  gbn_sender_on_timeout(&sender, 125, &actions);
  TEST_ASSERT_EQUAL_INT(2, actions.packet_count);
  TEST_ASSERT_EQUAL_UINT32(0U, actions.packets[0].seq);
  TEST_ASSERT_EQUAL_UINT32(1U, actions.packets[1].seq);
  TEST_ASSERT_EQUAL_INT64(150, actions.timer_deadline_ms);

  for (timeout = 2; timeout <= 10; ++timeout) {
    gbn_sender_on_timeout(&sender, 100 + timeout * 25, &actions);
  }
  TEST_ASSERT_TRUE(sender.failed);
  TEST_ASSERT_TRUE(actions.failed);
  TEST_ASSERT_EQUAL_INT(0, actions.packet_count);
}

void test_sender_rejects_invalid_setup_and_ignores_invalid_acks(void) {
  transfer_packet data[1];
  transfer_packet ack;
  gbn_sender sender;
  gbn_sender completed_sender;
  gbn_actions actions;

  make_data_packets(data, 1U);
  TEST_ASSERT_FALSE(gbn_sender_init(NULL, data, 1U, 1U, 100));
  TEST_ASSERT_FALSE(gbn_sender_init(&sender, NULL, 1U, 1U, 100));
  TEST_ASSERT_FALSE(gbn_sender_init(&sender, data, 1U, 0U, 100));
  TEST_ASSERT_FALSE(gbn_sender_init(&sender, data, 1U, 65U, 100));
  TEST_ASSERT_FALSE(gbn_sender_init(&sender, data, 1U, 1U, 0));
  data[0].seq = 1U;
  TEST_ASSERT_FALSE(gbn_sender_init(&sender, data, 1U, 1U, 100));
  data[0].seq = 0U;
  data[0].type = PACKET_FIN;
  TEST_ASSERT_FALSE(gbn_sender_init(&sender, data, 1U, 1U, 100));
  data[0].type = PACKET_DATA;
  data[0].length = PACKET_MAX_PAYLOAD + 1U;
  TEST_ASSERT_FALSE(gbn_sender_init(&sender, data, 1U, 1U, 100));

  data[0].length = 1U;
  TEST_ASSERT_TRUE(gbn_sender_init(&sender, data, 1U, 1U, 100));
  gbn_sender_start(&sender, 0, &actions);
  memset(&ack, 0, sizeof(ack));
  ack.type = PACKET_DATA;
  ack.seq = 1U;
  gbn_sender_on_ack(&sender, &ack, 1, &actions);
  TEST_ASSERT_EQUAL_UINT32(0U, sender.base);
  TEST_ASSERT_EQUAL_INT(0, actions.packet_count);
  ack.type = PACKET_ACK;
  ack.seq = 2U;
  gbn_sender_on_ack(&sender, &ack, 1, &actions);
  TEST_ASSERT_EQUAL_UINT32(0U, sender.base);
  TEST_ASSERT_EQUAL_INT(0, actions.packet_count);

  ack.seq = 1U;
  gbn_sender_on_ack(&sender, &ack, 2, &actions);
  TEST_ASSERT_EQUAL_INT(1, actions.packet_count);
  TEST_ASSERT_EQUAL_INT(PACKET_FIN, actions.packets[0].type);
  gbn_sender_on_ack(&sender, NULL, 3, &actions);
  TEST_ASSERT_EQUAL_INT(0, actions.packet_count);
  gbn_sender_on_ack(NULL, &ack, 3, &actions);
  TEST_ASSERT_EQUAL_INT(0, actions.packet_count);

  TEST_ASSERT_TRUE(gbn_sender_init(&completed_sender, NULL, 0U, 1U, 100));
  gbn_sender_start(&completed_sender, 0, &actions);
  ack.type = PACKET_ACK;
  ack.seq = 1U;
  gbn_sender_on_ack(&completed_sender, &ack, 1, &actions);
  gbn_sender_on_ack(&completed_sender, &ack, 2, &actions);
  TEST_ASSERT_EQUAL_INT(0, actions.packet_count);
}

void test_sender_timeout_without_timer_does_nothing(void) {
  gbn_sender sender;
  gbn_actions actions;

  TEST_ASSERT_TRUE(gbn_sender_init(&sender, NULL, 0U, 1U, 10));
  gbn_sender_on_timeout(&sender, 100, &actions);
  TEST_ASSERT_EQUAL_INT(0, actions.packet_count);
  gbn_sender_start(&sender, 0, &actions);
  gbn_sender_on_timeout(&sender, 9, &actions);
  TEST_ASSERT_EQUAL_INT(0, actions.packet_count);
  TEST_ASSERT_TRUE(actions.timer_running);
  gbn_sender_on_timeout(NULL, 100, &actions);
  TEST_ASSERT_EQUAL_INT(0, actions.packet_count);
  gbn_sender_start(NULL, 0, &actions);
  TEST_ASSERT_EQUAL_INT(0, actions.packet_count);

  TEST_ASSERT_TRUE(gbn_sender_init(&sender, NULL, 0U, 1U, 10));
  sender.completed = 1;
  gbn_sender_start(&sender, 0, &actions);
  TEST_ASSERT_EQUAL_INT(0, actions.packet_count);
  sender.completed = 0;
  sender.failed = 1;
  gbn_sender_start(&sender, 0, &actions);
  TEST_ASSERT_EQUAL_INT(0, actions.packet_count);
}

void test_receiver_discards_gaps_and_lingers_for_fin(void) {
  gbn_receiver receiver;
  gbn_actions actions;
  transfer_packet packet;

  gbn_receiver_init(&receiver, 0);
  memset(&packet, 0, sizeof(packet));
  packet.type = PACKET_DATA;
  packet.seq = 1U;
  packet.length = 1U;
  packet.payload[0] = 'x';
  gbn_receiver_on_packet(&receiver, &packet, 10, &actions);
  TEST_ASSERT_FALSE(actions.deliver_payload);
  TEST_ASSERT_EQUAL_INT(1, actions.packet_count);
  TEST_ASSERT_EQUAL_UINT32(0U, actions.packets[0].seq);

  packet.seq = 0U;
  packet.payload[0] = 'a';
  gbn_receiver_on_packet(&receiver, &packet, 20, &actions);
  TEST_ASSERT_TRUE(actions.deliver_payload);
  TEST_ASSERT_EQUAL_INT(1, actions.payload_length);
  TEST_ASSERT_EQUAL_MEMORY("a", actions.payload, 1U);
  TEST_ASSERT_EQUAL_UINT32(1U, actions.packets[0].seq);

  gbn_receiver_on_packet(&receiver, &packet, 25, &actions);
  TEST_ASSERT_FALSE(actions.deliver_payload);
  TEST_ASSERT_EQUAL_UINT32(1U, actions.packets[0].seq);

  packet.type = PACKET_FIN;
  packet.seq = 1U;
  packet.length = 0U;
  gbn_receiver_on_packet(&receiver, &packet, 30, &actions);
  TEST_ASSERT_TRUE(actions.finish_output);
  TEST_ASSERT_EQUAL_INT(GBN_RECEIVER_LINGERING, receiver.phase);
  TEST_ASSERT_EQUAL_UINT32(2U, actions.packets[0].seq);

  gbn_receiver_on_packet(&receiver, &packet, 40, &actions);
  TEST_ASSERT_EQUAL_INT(1, actions.packet_count);
  TEST_ASSERT_EQUAL_UINT32(2U, actions.packets[0].seq);
  TEST_ASSERT_EQUAL_INT64(2030, actions.timer_deadline_ms);

  gbn_receiver_on_timeout(&receiver, 2029, &actions);
  TEST_ASSERT_FALSE(actions.completed);
  gbn_receiver_on_timeout(&receiver, 2030, &actions);
  TEST_ASSERT_TRUE(actions.completed);
  TEST_ASSERT_EQUAL_INT(GBN_RECEIVER_COMPLETED, receiver.phase);
}

void test_receiver_ignores_other_packet_types_and_terminal_events(void) {
  gbn_receiver receiver;
  gbn_actions actions;
  transfer_packet packet;

  gbn_receiver_init(&receiver, 0);
  memset(&packet, 0, sizeof(packet));
  packet.type = PACKET_ACK;
  gbn_receiver_on_packet(&receiver, &packet, 1, &actions);
  TEST_ASSERT_EQUAL_INT(0, actions.packet_count);
  TEST_ASSERT_TRUE(actions.timer_running);
  gbn_receiver_on_packet(NULL, &packet, 1, &actions);
  TEST_ASSERT_EQUAL_INT(0, actions.packet_count);
  gbn_receiver_on_packet(&receiver, NULL, 1, &actions);
  TEST_ASSERT_EQUAL_INT(0, actions.packet_count);

  packet.type = PACKET_FIN;
  packet.seq = 4U;
  gbn_receiver_on_packet(&receiver, &packet, 2, &actions);
  TEST_ASSERT_FALSE(actions.finish_output);
  TEST_ASSERT_EQUAL_UINT32(0U, actions.packets[0].seq);

  packet.type = PACKET_DATA;
  packet.seq = 0U;
  gbn_receiver_on_packet(&receiver, &packet, GBN_RECEIVE_IDLE_MS + 2,
                         &actions);
  TEST_ASSERT_TRUE(actions.failed);
  gbn_receiver_on_packet(&receiver, &packet, GBN_RECEIVE_IDLE_MS + 3,
                         &actions);
  TEST_ASSERT_EQUAL_INT(0, actions.packet_count);

  gbn_receiver_init(&receiver, 0);
  packet.type = PACKET_FIN;
  packet.seq = 0U;
  gbn_receiver_on_packet(&receiver, &packet, 1, &actions);
  TEST_ASSERT_TRUE(actions.finish_output);
  packet.type = PACKET_DATA;
  gbn_receiver_on_packet(&receiver, &packet, 2, &actions);
  TEST_ASSERT_EQUAL_INT(0, actions.packet_count);
  gbn_receiver_on_packet(&receiver, &packet, GBN_FIN_LINGER_MS + 2,
                         &actions);
  TEST_ASSERT_TRUE(actions.completed);
  gbn_receiver_on_packet(&receiver, &packet, GBN_FIN_LINGER_MS + 3,
                         &actions);
  TEST_ASSERT_EQUAL_INT(0, actions.packet_count);
  gbn_receiver_on_packet(NULL, &packet, 1, &actions);
  gbn_receiver_on_timeout(NULL, 1, &actions);
}

void test_empty_and_exact_multiple_packet_sequences(void) {
  transfer_packet full_packets[2];
  gbn_sender sender;
  gbn_actions actions;
  transfer_packet ack;
  uint32_t index;

  TEST_ASSERT_TRUE(gbn_sender_init(&sender, NULL, 0U, 8U, 100));
  gbn_sender_start(&sender, 0, &actions);
  TEST_ASSERT_EQUAL_INT(1, actions.packet_count);
  TEST_ASSERT_EQUAL_INT(PACKET_FIN, actions.packets[0].type);
  TEST_ASSERT_EQUAL_UINT32(0U, actions.packets[0].seq);
  memset(&ack, 0, sizeof(ack));
  ack.type = PACKET_ACK;
  ack.seq = 1U;
  gbn_sender_on_ack(&sender, &ack, 1, &actions);
  TEST_ASSERT_TRUE(sender.completed);

  for (index = 0U; index < 2U; ++index) {
    memset(&full_packets[index], 0, sizeof(full_packets[index]));
    full_packets[index].type = PACKET_DATA;
    full_packets[index].seq = index;
    full_packets[index].length = PACKET_MAX_PAYLOAD;
    memset(full_packets[index].payload, (int)('a' + index),
           PACKET_MAX_PAYLOAD);
  }
  TEST_ASSERT_TRUE(gbn_sender_init(&sender, full_packets, 2U, 8U, 100));
  gbn_sender_start(&sender, 0, &actions);
  TEST_ASSERT_EQUAL_INT(2, actions.packet_count);
  TEST_ASSERT_EQUAL_INT(PACKET_DATA, actions.packets[0].type);
  TEST_ASSERT_EQUAL_INT(PACKET_DATA, actions.packets[1].type);
  TEST_ASSERT_EQUAL_INT(PACKET_MAX_PAYLOAD, actions.packets[0].length);
  TEST_ASSERT_EQUAL_INT(PACKET_MAX_PAYLOAD, actions.packets[1].length);

  ack.seq = 2U;
  gbn_sender_on_ack(&sender, &ack, 10, &actions);
  TEST_ASSERT_EQUAL_INT(1, actions.packet_count);
  TEST_ASSERT_EQUAL_INT(PACKET_FIN, actions.packets[0].type);
  TEST_ASSERT_EQUAL_UINT32(2U, actions.packets[0].seq);
}

void test_file_packetizer_handles_empty_and_exact_multiple_files(void) {
  FILE *input;
  transfer_packet *packets = NULL;
  size_t packet_count = 99U;
  unsigned char bytes[2U * PACKET_MAX_PAYLOAD];
  size_t index;

  TEST_ASSERT_EQUAL_INT(FILE_PACKETS_READ_ERROR,
                       file_packets_read(NULL, &packets, &packet_count));

  input = tmpfile();
  TEST_ASSERT_NOT_NULL(input);
  TEST_ASSERT_EQUAL_INT(FILE_PACKETS_OK,
                       file_packets_read(input, &packets, &packet_count));
  TEST_ASSERT_EQUAL_INT(0, packet_count);
  TEST_ASSERT_NULL(packets);
  TEST_ASSERT_EQUAL_INT(0, fclose(input));

  for (index = 0U; index < sizeof(bytes); ++index) {
    bytes[index] = (unsigned char)(index & 0xffU);
  }
  input = tmpfile();
  TEST_ASSERT_NOT_NULL(input);
  TEST_ASSERT_EQUAL_INT(sizeof(bytes),
                        fwrite(bytes, 1U, sizeof(bytes), input));
  TEST_ASSERT_EQUAL_INT(0, fseek(input, 0L, SEEK_SET));
  TEST_ASSERT_EQUAL_INT(FILE_PACKETS_OK,
                       file_packets_read(input, &packets, &packet_count));
  TEST_ASSERT_EQUAL_INT(2, packet_count);
  TEST_ASSERT_EQUAL_UINT32(0U, packets[0].seq);
  TEST_ASSERT_EQUAL_UINT32(1U, packets[1].seq);
  TEST_ASSERT_EQUAL_INT(PACKET_MAX_PAYLOAD, packets[0].length);
  TEST_ASSERT_EQUAL_INT(PACKET_MAX_PAYLOAD, packets[1].length);
  TEST_ASSERT_EQUAL_MEMORY(bytes, packets[0].payload, PACKET_MAX_PAYLOAD);
  TEST_ASSERT_EQUAL_MEMORY(bytes + PACKET_MAX_PAYLOAD, packets[1].payload,
                           PACKET_MAX_PAYLOAD);
  free(packets);
  packets = NULL;
  TEST_ASSERT_EQUAL_INT(0, fclose(input));
}

void test_file_packetizer_rejects_invalid_arguments_and_large_files(void) {
  FILE *input;
  transfer_packet *packets = NULL;
  size_t packet_count = 10U;

  TEST_ASSERT_EQUAL_INT(FILE_PACKETS_READ_ERROR,
                       file_packets_read(NULL, NULL, &packet_count));
  TEST_ASSERT_EQUAL_INT(FILE_PACKETS_READ_ERROR,
                       file_packets_read(NULL, &packets, NULL));
  TEST_ASSERT_EQUAL_INT(FILE_PACKETS_READ_ERROR,
                       file_packets_read(NULL, &packets, &packet_count));
  TEST_ASSERT_NULL(packets);
  TEST_ASSERT_EQUAL_INT(0, packet_count);

  input = tmpfile();
  TEST_ASSERT_NOT_NULL(input);
  TEST_ASSERT_EQUAL_INT(0, fseek(input, 16L * 1024L * 1024L, SEEK_SET));
  TEST_ASSERT_EQUAL_INT('x', fputc('x', input));
  TEST_ASSERT_EQUAL_INT(0, fseek(input, 0L, SEEK_SET));
  TEST_ASSERT_EQUAL_INT(FILE_PACKETS_TOO_LARGE,
                       file_packets_read(input, &packets, &packet_count));
  TEST_ASSERT_NULL(packets);
  TEST_ASSERT_EQUAL_INT(0, packet_count);
  TEST_ASSERT_EQUAL_INT(0, fclose(input));
}

void test_file_packetizer_splits_2500_bytes_as_documented(void) {
  FILE *input = tmpfile();
  transfer_packet *packets = NULL;
  size_t packet_count = 0U;
  unsigned char bytes[2500];
  size_t index;

  TEST_ASSERT_NOT_NULL(input);
  for (index = 0U; index < sizeof(bytes); ++index) {
    bytes[index] = (unsigned char)(index & 0xffU);
  }
  TEST_ASSERT_EQUAL_INT(sizeof(bytes), fwrite(bytes, 1U, sizeof(bytes), input));
  TEST_ASSERT_EQUAL_INT(0, fseek(input, 0L, SEEK_SET));
  TEST_ASSERT_EQUAL_INT(FILE_PACKETS_OK,
                       file_packets_read(input, &packets, &packet_count));
  TEST_ASSERT_EQUAL_INT(3, packet_count);
  TEST_ASSERT_EQUAL_UINT32(0U, packets[0].seq);
  TEST_ASSERT_EQUAL_INT(1024, packets[0].length);
  TEST_ASSERT_EQUAL_MEMORY(bytes, packets[0].payload, 1024U);
  TEST_ASSERT_EQUAL_UINT32(1U, packets[1].seq);
  TEST_ASSERT_EQUAL_INT(1024, packets[1].length);
  TEST_ASSERT_EQUAL_MEMORY(bytes + 1024U, packets[1].payload, 1024U);
  TEST_ASSERT_EQUAL_UINT32(2U, packets[2].seq);
  TEST_ASSERT_EQUAL_INT(452, packets[2].length);
  TEST_ASSERT_EQUAL_MEMORY(bytes + 2048U, packets[2].payload, 452U);
  free(packets);
  TEST_ASSERT_EQUAL_INT(0, fclose(input));
}

void test_receiver_times_out_without_valid_packets(void) {
  gbn_receiver receiver;
  gbn_actions actions;

  gbn_receiver_init(&receiver, 15);
  gbn_receiver_on_timeout(&receiver, GBN_RECEIVE_IDLE_MS + 14, &actions);
  TEST_ASSERT_FALSE(actions.failed);
  gbn_receiver_on_timeout(&receiver, GBN_RECEIVE_IDLE_MS + 15, &actions);
  TEST_ASSERT_TRUE(actions.failed);
  TEST_ASSERT_EQUAL_INT(GBN_RECEIVER_FAILED, receiver.phase);
}

void test_state_machines_recover_from_a_dropped_packet(void) {
  transfer_packet data[3];
  gbn_sender sender;
  gbn_receiver receiver;
  gbn_actions send_actions;
  gbn_actions receive_actions;
  transfer_packet ack;
  int64_t now = 0;
  size_t index;

  make_data_packets(data, 3U);
  TEST_ASSERT_TRUE(gbn_sender_init(&sender, data, 3U, 2U, 100));
  gbn_receiver_init(&receiver, now);
  gbn_sender_start(&sender, now, &send_actions);

  for (index = 0U; index < send_actions.packet_count; ++index) {
    if (send_actions.packets[index].seq == 0U) {
      gbn_receiver_on_packet(&receiver, &send_actions.packets[index], now,
                             &receive_actions);
      ack = receive_actions.packets[0];
    }
  }
  gbn_sender_on_ack(&sender, &ack, 10, &send_actions);
  TEST_ASSERT_EQUAL_INT(1, send_actions.packet_count);
  TEST_ASSERT_EQUAL_UINT32(2U, send_actions.packets[0].seq);

  gbn_receiver_on_packet(&receiver, &send_actions.packets[0], 20,
                         &receive_actions);
  TEST_ASSERT_FALSE(receive_actions.deliver_payload);
  ack = receive_actions.packets[0];
  gbn_sender_on_ack(&sender, &ack, 20, &send_actions);
  TEST_ASSERT_EQUAL_UINT32(1U, sender.base);

  gbn_sender_on_timeout(&sender, 110, &send_actions);
  TEST_ASSERT_EQUAL_INT(2, send_actions.packet_count);
  TEST_ASSERT_EQUAL_UINT32(1U, send_actions.packets[0].seq);
  TEST_ASSERT_EQUAL_UINT32(2U, send_actions.packets[1].seq);

  for (index = 0U; index < send_actions.packet_count; ++index) {
    gbn_receiver_on_packet(&receiver, &send_actions.packets[index], 120,
                           &receive_actions);
    TEST_ASSERT_TRUE(receive_actions.deliver_payload);
    ack = receive_actions.packets[0];
  }
  gbn_sender_on_ack(&sender, &ack, 130, &send_actions);
  TEST_ASSERT_EQUAL_INT(1, send_actions.packet_count);
  TEST_ASSERT_EQUAL_INT(PACKET_FIN, send_actions.packets[0].type);

  gbn_receiver_on_packet(&receiver, &send_actions.packets[0], 140,
                         &receive_actions);
  TEST_ASSERT_TRUE(receive_actions.finish_output);
  ack = receive_actions.packets[0];
  gbn_sender_on_ack(&sender, &ack, 150, &send_actions);
  TEST_ASSERT_TRUE(sender.completed);
}

void test_cumulative_ack_covers_lost_earlier_acks(void) {
  transfer_packet data[5];
  transfer_packet ack;
  gbn_sender sender;
  gbn_actions actions;

  make_data_packets(data, 5U);
  TEST_ASSERT_TRUE(gbn_sender_init(&sender, data, 5U, 3U, 100));
  gbn_sender_start(&sender, 0, &actions);
  TEST_ASSERT_EQUAL_INT(3, actions.packet_count);

  memset(&ack, 0, sizeof(ack));
  ack.type = PACKET_ACK;
  ack.seq = 2U;
  gbn_sender_on_ack(&sender, &ack, 25, &actions);
  TEST_ASSERT_EQUAL_UINT32(2U, sender.base);
  TEST_ASSERT_EQUAL_INT(2, actions.packet_count);
  TEST_ASSERT_EQUAL_UINT32(3U, actions.packets[0].seq);
  TEST_ASSERT_EQUAL_UINT32(4U, actions.packets[1].seq);

  ack.seq = 5U;
  gbn_sender_on_ack(&sender, &ack, 30, &actions);
  TEST_ASSERT_EQUAL_UINT32(5U, sender.base);
  TEST_ASSERT_EQUAL_INT(1, actions.packet_count);
  TEST_ASSERT_EQUAL_INT(PACKET_FIN, actions.packets[0].type);
  TEST_ASSERT_EQUAL_UINT32(5U, actions.packets[0].seq);
}

void test_state_machines_transfer_with_damaged_channels(void) {
  static const uint32_t seeds[] = {7U, 41U, 2025U, 65537U, 0xdeadbeefU};
  size_t index;
  unsigned int damage_flags = 0U;

  for (index = 0U; index < sizeof(seeds) / sizeof(seeds[0]); ++index) {
    TEST_ASSERT_TRUE(
        run_damaged_state_machine_transfer(seeds[index], &damage_flags));
  }
  TEST_ASSERT_EQUAL_HEX32(0x3fU, damage_flags);
}

int main(void) {
  UNITY_BEGIN();
  RUN_TEST(test_get_greeting);
  RUN_TEST(test_parse_send_arguments);
  RUN_TEST(test_parse_rejects_invalid_arguments);
  RUN_TEST(test_parse_rejects_invalid_session_and_probabilities);
  RUN_TEST(test_transfer_io_drives_state_machines_with_mock_relay);
  RUN_TEST(test_transfer_io_registration_retries_and_failures);
  RUN_TEST(test_transfer_io_sender_retransmission_corrupt_ack_and_timeout);
  RUN_TEST(test_transfer_io_input_and_socket_setup_failures);
  RUN_TEST(test_cli_usage_and_invalid_input_paths);
  RUN_TEST(test_packet_checksum_example);
  RUN_TEST(test_packet_checksum_odd_length);
  RUN_TEST(test_packet_encode_decode);
  RUN_TEST(test_packet_wire_bytes_match_protocol_example);
  RUN_TEST(test_packet_decoder_rejects_malformed_datagrams);
  RUN_TEST(test_packet_encoder_rejects_invalid_inputs);
  RUN_TEST(test_packet_decoder_rejects_invalid_header_fields);
  RUN_TEST(test_sender_window_cumulative_ack_and_fin);
  RUN_TEST(test_sender_timeout_retransmits_and_gives_up);
  RUN_TEST(test_sender_rejects_invalid_setup_and_ignores_invalid_acks);
  RUN_TEST(test_sender_timeout_without_timer_does_nothing);
  RUN_TEST(test_receiver_discards_gaps_and_lingers_for_fin);
  RUN_TEST(test_receiver_ignores_other_packet_types_and_terminal_events);
  RUN_TEST(test_receiver_times_out_without_valid_packets);
  RUN_TEST(test_empty_and_exact_multiple_packet_sequences);
  RUN_TEST(test_file_packetizer_handles_empty_and_exact_multiple_files);
  RUN_TEST(test_file_packetizer_splits_2500_bytes_as_documented);
  RUN_TEST(test_file_packetizer_rejects_invalid_arguments_and_large_files);
  RUN_TEST(test_state_machines_recover_from_a_dropped_packet);
  RUN_TEST(test_cumulative_ack_covers_lost_earlier_acks);
  RUN_TEST(test_state_machines_transfer_with_damaged_channels);
  return UNITY_END();
}
