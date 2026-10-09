#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "harness/unity.h"
#include "../src/cli.h"
#include "../src/gbn.h"
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

void test_receiver_times_out_without_valid_packets(void) {
  gbn_receiver receiver;
  gbn_actions actions;

  gbn_receiver_init(&receiver, 15);
  gbn_receiver_on_timeout(&receiver, 30014, &actions);
  TEST_ASSERT_FALSE(actions.failed);
  gbn_receiver_on_timeout(&receiver, 30015, &actions);
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

int main(void) {
  UNITY_BEGIN();
  RUN_TEST(test_get_greeting);
  RUN_TEST(test_parse_send_arguments);
  RUN_TEST(test_parse_rejects_invalid_arguments);
  RUN_TEST(test_parse_rejects_invalid_session_and_probabilities);
  RUN_TEST(test_packet_checksum_example);
  RUN_TEST(test_packet_encode_decode);
  RUN_TEST(test_sender_window_cumulative_ack_and_fin);
  RUN_TEST(test_sender_timeout_retransmits_and_gives_up);
  RUN_TEST(test_receiver_discards_gaps_and_lingers_for_fin);
  RUN_TEST(test_receiver_times_out_without_valid_packets);
  RUN_TEST(test_state_machines_recover_from_a_dropped_packet);
  return UNITY_END();
}
