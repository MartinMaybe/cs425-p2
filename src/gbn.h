#ifndef GBN_H
#define GBN_H

#include "packet.h"

#include <stddef.h>
#include <stdint.h>

#define GBN_MAX_WINDOW 64U
#define GBN_MAX_ACTION_PACKETS (GBN_MAX_WINDOW + 1U)
#define GBN_RECEIVE_IDLE_MS INT64_C(30000)
#define GBN_FIN_LINGER_MS INT64_C(2000)

typedef struct {
  transfer_packet packets[GBN_MAX_ACTION_PACKETS];
  size_t packet_count;
  unsigned char payload[PACKET_MAX_PAYLOAD];
  uint16_t payload_length;
  int deliver_payload;
  int finish_output;
  int completed;
  int failed;
  int timer_running;
  int64_t timer_deadline_ms;
} gbn_actions;

typedef struct {
  const transfer_packet *data_packets;
  uint32_t data_count;
  uint32_t window_size;
  uint32_t base;
  uint32_t next;
  uint32_t consecutive_timeouts;
  int64_t timeout_ms;
  int64_t timer_deadline_ms;
  int timer_running;
  int fin_sent;
  int completed;
  int failed;
} gbn_sender;

typedef enum {
  GBN_RECEIVER_ACTIVE,
  GBN_RECEIVER_LINGERING,
  GBN_RECEIVER_COMPLETED,
  GBN_RECEIVER_FAILED
} gbn_receiver_phase;

typedef struct {
  uint32_t expected;
  uint32_t fin_sequence;
  int64_t idle_deadline_ms;
  int64_t linger_deadline_ms;
  gbn_receiver_phase phase;
} gbn_receiver;

int gbn_sender_init(gbn_sender *sender, const transfer_packet *data_packets,
                    uint32_t data_count, uint32_t window_size,
                    int64_t timeout_ms);
void gbn_sender_start(gbn_sender *sender, int64_t now_ms,
                      gbn_actions *actions);
void gbn_sender_on_ack(gbn_sender *sender, const transfer_packet *ack,
                       int64_t now_ms, gbn_actions *actions);
void gbn_sender_on_timeout(gbn_sender *sender, int64_t now_ms,
                           gbn_actions *actions);

void gbn_receiver_init(gbn_receiver *receiver, int64_t now_ms);
void gbn_receiver_on_packet(gbn_receiver *receiver,
                            const transfer_packet *packet, int64_t now_ms,
                            gbn_actions *actions);
void gbn_receiver_on_timeout(gbn_receiver *receiver, int64_t now_ms,
                             gbn_actions *actions);

#endif
