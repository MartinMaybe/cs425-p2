#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "harness/unity.h"
#include "../src/cli.h"
#include "../src/lab.h"
#include "../src/packet.h"


void setUp(void) {
  printf("Setting up tests...\n");
}

void tearDown(void) {
  printf("Tearing down tests...\n");
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

void test_packet_checksum_example(void) {
  const unsigned char example[] = {
    0x00, 0x01, 0xf2, 0x03, 0xf4, 0xf5, 0xf6, 0xf7
  };

  TEST_ASSERT_EQUAL_HEX16(0x220d, packet_checksum(example, sizeof(example)));
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

int main(void) {
  UNITY_BEGIN();
  RUN_TEST(test_get_greeting);
  RUN_TEST(test_parse_send_arguments);
  RUN_TEST(test_parse_rejects_invalid_arguments);
  RUN_TEST(test_parse_rejects_invalid_session_and_probabilities);
  RUN_TEST(test_packet_checksum_example);
  RUN_TEST(test_packet_encode_decode);
  return UNITY_END();
}
