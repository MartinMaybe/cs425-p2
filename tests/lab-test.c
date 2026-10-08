#include <stdlib.h>
#include <stdio.h>
#include "harness/unity.h"
#include "../src/cli.h"
#include "../src/lab.h"


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
    "-l", "0.1", "-c", "0.2", "-d", "1", "-p", "4250",
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
  TEST_ASSERT_EQUAL_FLOAT(1.0, options.duplicate);
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

int main(void) {
  UNITY_BEGIN();
  RUN_TEST(test_get_greeting);
  RUN_TEST(test_parse_send_arguments);
  RUN_TEST(test_parse_rejects_invalid_arguments);
  return UNITY_END();
}
