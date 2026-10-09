#include "gbn.h"

#include <string.h>

static void clear_actions(gbn_actions *actions)
{
  memset(actions, 0, sizeof(*actions));
}

static void add_packet(gbn_actions *actions, const transfer_packet *packet)
{
  if (actions->packet_count < GBN_MAX_ACTION_PACKETS) {
    actions->packets[actions->packet_count] = *packet;
    ++actions->packet_count;
  } else {
    actions->failed = 1;
  }
}

static void set_sender_timer(gbn_sender *sender, int64_t now_ms,
                             gbn_actions *actions)
{
  sender->timer_running = 1;
  sender->timer_deadline_ms = now_ms + sender->timeout_ms;
  actions->timer_running = 1;
  actions->timer_deadline_ms = sender->timer_deadline_ms;
}

static void stop_sender_timer(gbn_sender *sender, gbn_actions *actions)
{
  sender->timer_running = 0;
  actions->timer_running = 0;
}

static void send_fin(gbn_sender *sender, int64_t now_ms,
                     gbn_actions *actions)
{
  transfer_packet fin;

  memset(&fin, 0, sizeof(fin));
  fin.type = PACKET_FIN;
  fin.seq = sender->data_count;
  sender->fin_sent = 1;
  add_packet(actions, &fin);
  set_sender_timer(sender, now_ms, actions);
}

static void fill_window(gbn_sender *sender, int64_t now_ms,
                        gbn_actions *actions)
{
  while (sender->next < sender->data_count &&
         sender->next - sender->base < sender->window_size) {
    add_packet(actions, &sender->data_packets[sender->next]);
    ++sender->next;
    if (!sender->timer_running) {
      set_sender_timer(sender, now_ms, actions);
    }
  }

  if (sender->base == sender->data_count &&
      sender->next == sender->data_count && !sender->fin_sent) {
    send_fin(sender, now_ms, actions);
  } else if (sender->timer_running) {
    actions->timer_running = 1;
    actions->timer_deadline_ms = sender->timer_deadline_ms;
  }
}

int gbn_sender_init(gbn_sender *sender, const transfer_packet *data_packets,
                    uint32_t data_count, uint32_t window_size,
                    int64_t timeout_ms)
{
  uint32_t index;

  if (sender == NULL || (data_count > 0U && data_packets == NULL) ||
      window_size == 0U || window_size > GBN_MAX_WINDOW || timeout_ms <= 0) {
    return 0;
  }
  for (index = 0U; index < data_count; ++index) {
    if (data_packets[index].type != PACKET_DATA ||
        data_packets[index].seq != index ||
        data_packets[index].length > PACKET_MAX_PAYLOAD) {
      return 0;
    }
  }

  memset(sender, 0, sizeof(*sender));
  sender->data_packets = data_packets;
  sender->data_count = data_count;
  sender->window_size = window_size;
  sender->timeout_ms = timeout_ms;
  return 1;
}

void gbn_sender_start(gbn_sender *sender, int64_t now_ms,
                      gbn_actions *actions)
{
  clear_actions(actions);
  if (sender == NULL || sender->completed || sender->failed) {
    return;
  }
  fill_window(sender, now_ms, actions);
}

void gbn_sender_on_ack(gbn_sender *sender, const transfer_packet *ack,
                       int64_t now_ms, gbn_actions *actions)
{
  uint32_t acknowledged;

  clear_actions(actions);
  if (sender == NULL || ack == NULL || ack->type != PACKET_ACK ||
      sender->completed || sender->failed) {
    return;
  }
  if (sender->fin_sent && ack->seq == sender->data_count + 1U) {
    sender->base = ack->seq;
    sender->completed = 1;
    sender->consecutive_timeouts = 0U;
    stop_sender_timer(sender, actions);
    actions->completed = 1;
    return;
  }
  if (ack->seq <= sender->base || ack->seq > sender->next ||
      sender->fin_sent) {
    if (sender->timer_running) {
      actions->timer_running = 1;
      actions->timer_deadline_ms = sender->timer_deadline_ms;
    }
    return;
  }

  acknowledged = ack->seq;
  sender->base = acknowledged;
  sender->consecutive_timeouts = 0U;
  if (sender->base == sender->next) {
    stop_sender_timer(sender, actions);
  } else {
    set_sender_timer(sender, now_ms, actions);
  }
  fill_window(sender, now_ms, actions);
}

void gbn_sender_on_timeout(gbn_sender *sender, int64_t now_ms,
                           gbn_actions *actions)
{
  uint32_t sequence;

  clear_actions(actions);
  if (sender == NULL || sender->completed || sender->failed ||
      !sender->timer_running || now_ms < sender->timer_deadline_ms) {
    if (sender != NULL && sender->timer_running) {
      actions->timer_running = 1;
      actions->timer_deadline_ms = sender->timer_deadline_ms;
    }
    return;
  }

  ++sender->consecutive_timeouts;
  if (sender->consecutive_timeouts >= 10U) {
    sender->failed = 1;
    sender->timer_running = 0;
    actions->failed = 1;
    return;
  }

  if (sender->fin_sent) {
    transfer_packet fin;
    memset(&fin, 0, sizeof(fin));
    fin.type = PACKET_FIN;
    fin.seq = sender->data_count;
    add_packet(actions, &fin);
  } else {
    for (sequence = sender->base; sequence < sender->next; ++sequence) {
      add_packet(actions, &sender->data_packets[sequence]);
    }
  }
  set_sender_timer(sender, now_ms, actions);
}

void gbn_receiver_init(gbn_receiver *receiver, int64_t now_ms)
{
  memset(receiver, 0, sizeof(*receiver));
  receiver->phase = GBN_RECEIVER_ACTIVE;
  receiver->idle_deadline_ms = now_ms + GBN_RECEIVE_IDLE_MS;
}

void gbn_receiver_on_packet(gbn_receiver *receiver,
                            const transfer_packet *packet, int64_t now_ms,
                            gbn_actions *actions)
{
  transfer_packet ack;

  clear_actions(actions);
  if (receiver == NULL || packet == NULL ||
      receiver->phase == GBN_RECEIVER_COMPLETED ||
      receiver->phase == GBN_RECEIVER_FAILED) {
    return;
  }
  if (receiver->phase == GBN_RECEIVER_ACTIVE &&
      now_ms >= receiver->idle_deadline_ms) {
    gbn_receiver_on_timeout(receiver, now_ms, actions);
    return;
  }
  if (receiver->phase == GBN_RECEIVER_LINGERING &&
      now_ms >= receiver->linger_deadline_ms) {
    gbn_receiver_on_timeout(receiver, now_ms, actions);
    return;
  }
  if (receiver->phase == GBN_RECEIVER_ACTIVE) {
    receiver->idle_deadline_ms = now_ms + GBN_RECEIVE_IDLE_MS;
    if (packet->type == PACKET_DATA) {
      if (packet->seq == receiver->expected) {
        actions->deliver_payload = 1;
        actions->payload_length = packet->length;
        memcpy(actions->payload, packet->payload, packet->length);
        ++receiver->expected;
      }
      memset(&ack, 0, sizeof(ack));
      ack.type = PACKET_ACK;
      ack.seq = receiver->expected;
      add_packet(actions, &ack);
    } else if (packet->type == PACKET_FIN) {
      if (packet->seq == receiver->expected) {
        receiver->fin_sequence = packet->seq;
        receiver->phase = GBN_RECEIVER_LINGERING;
        receiver->linger_deadline_ms = now_ms + GBN_FIN_LINGER_MS;
        ++receiver->expected;
        actions->finish_output = 1;
      }
      memset(&ack, 0, sizeof(ack));
      ack.type = PACKET_ACK;
      ack.seq = receiver->expected;
      add_packet(actions, &ack);
    }
    if (receiver->phase == GBN_RECEIVER_ACTIVE) {
      actions->timer_running = 1;
      actions->timer_deadline_ms = receiver->idle_deadline_ms;
    } else {
      actions->timer_running = 1;
      actions->timer_deadline_ms = receiver->linger_deadline_ms;
    }
  } else if (receiver->phase == GBN_RECEIVER_LINGERING &&
             packet->type == PACKET_FIN &&
             packet->seq == receiver->fin_sequence) {
    memset(&ack, 0, sizeof(ack));
    ack.type = PACKET_ACK;
    ack.seq = receiver->expected;
    add_packet(actions, &ack);
    actions->timer_running = 1;
    actions->timer_deadline_ms = receiver->linger_deadline_ms;
  }
  if (receiver->phase == GBN_RECEIVER_LINGERING &&
      !actions->timer_running) {
    actions->timer_running = 1;
    actions->timer_deadline_ms = receiver->linger_deadline_ms;
  }
}

void gbn_receiver_on_timeout(gbn_receiver *receiver, int64_t now_ms,
                             gbn_actions *actions)
{
  clear_actions(actions);
  if (receiver == NULL) {
    return;
  }
  if (receiver->phase == GBN_RECEIVER_ACTIVE &&
      now_ms >= receiver->idle_deadline_ms) {
    receiver->phase = GBN_RECEIVER_FAILED;
    actions->failed = 1;
  } else if (receiver->phase == GBN_RECEIVER_LINGERING &&
             now_ms >= receiver->linger_deadline_ms) {
    receiver->phase = GBN_RECEIVER_COMPLETED;
    actions->completed = 1;
  } else if (receiver->phase == GBN_RECEIVER_ACTIVE) {
    actions->timer_running = 1;
    actions->timer_deadline_ms = receiver->idle_deadline_ms;
  } else if (receiver->phase == GBN_RECEIVER_LINGERING) {
    actions->timer_running = 1;
    actions->timer_deadline_ms = receiver->linger_deadline_ms;
  }
}
