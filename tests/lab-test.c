#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "harness/unity.h"
#include "../src/cli.h"
#include "../src/file_packets.h"
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
  set_wire_checksum(bytes, size);
  bytes[PACKET_HEADER_SIZE + 1U] ^= 0x01U;
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
  RUN_TEST(test_packet_checksum_example);
  RUN_TEST(test_packet_checksum_odd_length);
  RUN_TEST(test_packet_encode_decode);
  RUN_TEST(test_packet_wire_bytes_match_protocol_example);
  RUN_TEST(test_packet_decoder_rejects_malformed_datagrams);
  RUN_TEST(test_sender_window_cumulative_ack_and_fin);
  RUN_TEST(test_sender_timeout_retransmits_and_gives_up);
  RUN_TEST(test_receiver_discards_gaps_and_lingers_for_fin);
  RUN_TEST(test_receiver_times_out_without_valid_packets);
  RUN_TEST(test_empty_and_exact_multiple_packet_sequences);
  RUN_TEST(test_file_packetizer_handles_empty_and_exact_multiple_files);
  RUN_TEST(test_file_packetizer_splits_2500_bytes_as_documented);
  RUN_TEST(test_state_machines_recover_from_a_dropped_packet);
  RUN_TEST(test_cumulative_ack_covers_lost_earlier_acks);
  RUN_TEST(test_state_machines_transfer_with_damaged_channels);
  return UNITY_END();
}
