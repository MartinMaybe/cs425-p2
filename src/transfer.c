#define _POSIX_C_SOURCE 200809L

#include "transfer.h"

#include "file_packets.h"
#include "gbn.h"
#include "packet.h"

#include <errno.h>
#include <limits.h>
#include <poll.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#define REGISTRATION_ATTEMPTS 5
#define REGISTRATION_TIMEOUT_MS 1000
typedef struct {
  transfer_packet *packets;
  size_t count;
} packet_list;

static int64_t monotonic_milliseconds(void)
{
  struct timespec now;

  if (clock_gettime(CLOCK_MONOTONIC, &now) != 0) {
    return -1;
  }
  return ((int64_t)now.tv_sec * INT64_C(1000)) +
         ((int64_t)now.tv_nsec / INT64_C(1000000));
}

static int open_relay_socket(const cli_options *options)
{
  const struct addrinfo *address;
  int fd;

  for (address = options->relay_addresses; address != NULL;
       address = address->ai_next) {
    fd = socket(address->ai_family, address->ai_socktype, address->ai_protocol);
    if (fd < 0) {
      continue;
    }
    if (connect(fd, address->ai_addr, address->ai_addrlen) == 0) {
      return fd;
    }
    (void)close(fd);
  }
  (void)fprintf(stderr, "Unable to connect UDP socket to relay: %s\n",
                strerror(errno));
  return -1;
}

static int wait_readable(int fd, int timeout_ms)
{
  struct pollfd descriptor;
  int result;
  int64_t start = 0;
  int64_t deadline = 0;

  descriptor.fd = fd;
  descriptor.events = POLLIN;
  descriptor.revents = 0;
  if (timeout_ms > 0) {
    start = monotonic_milliseconds();
    if (start < 0) {
      return -1;
    }
    deadline = start + timeout_ms;
  }
  for (;;) {
    result = poll(&descriptor, 1U, timeout_ms);
    if (result >= 0 || errno != EINTR) {
      break;
    }
    if (timeout_ms == 0) {
      return 0;
    }
    {
      int64_t now = monotonic_milliseconds();
      int64_t remaining;
      if (now < 0) {
        return -1;
      }
      remaining = deadline - now;
      if (remaining <= 0) {
        return 0;
      }
      timeout_ms = remaining > (int64_t)INT_MAX ? INT_MAX : (int)remaining;
    }
  }
  if (result > 0 &&
      (descriptor.revents & (POLLERR | POLLHUP | POLLNVAL)) != 0) {
    errno = EIO;
    return -1;
  }
  return result;
}

static int register_receiver(int fd, const char *session)
{
  char hello[48];
  char reply[256];
  int hello_length;
  int attempt;

  hello_length = snprintf(hello, sizeof(hello), "HELLO %s recv", session);
  if (hello_length < 0 || (size_t)hello_length >= sizeof(hello)) {
    (void)fprintf(stderr, "Could not construct receiver registration.\n");
    return 0;
  }

  for (attempt = 0; attempt < REGISTRATION_ATTEMPTS; ++attempt) {
    int ready;
    ssize_t sent = send(fd, hello, (size_t)hello_length, 0);
    if (sent != hello_length) {
      (void)fprintf(stderr, "Could not send registration to relay: %s\n",
                    sent < 0 ? strerror(errno) : "short UDP datagram");
      return 0;
    }

    ready = wait_readable(fd, REGISTRATION_TIMEOUT_MS);
    if (ready < 0) {
      (void)fprintf(stderr, "Error waiting for relay registration: %s\n",
                    strerror(errno));
      return 0;
    }
    if (ready == 0) {
      continue;
    }

    {
      ssize_t received = recv(fd, reply, sizeof(reply) - 1U, 0);
      if (received < 0) {
        if (errno == EINTR) {
          --attempt;
          continue;
        }
        (void)fprintf(stderr, "Could not receive relay registration: %s\n",
                      strerror(errno));
        return 0;
      }
      reply[received] = '\0';
      if (received == 2 && memcmp(reply, "OK", 2U) == 0) {
        return 1;
      }
      if (received >= 4 && memcmp(reply, "ERR ", 4U) == 0) {
        (void)fprintf(stderr, "Relay refused registration: %s\n", reply + 4);
        return 0;
      }
      (void)fprintf(stderr, "Unexpected relay registration reply: %s\n", reply);
      return 0;
    }
  }

  (void)fprintf(stderr, "Relay registration timed out after %d attempts.\n",
                REGISTRATION_ATTEMPTS);
  return 0;
}

static int send_protocol_packets(int fd, const gbn_actions *actions)
{
  size_t index;

  for (index = 0U; index < actions->packet_count; ++index) {
    unsigned char bytes[PACKET_MAX_SIZE];
    size_t packet_size;
    ssize_t sent;

    if (!packet_encode(&actions->packets[index], bytes, sizeof(bytes),
                       &packet_size)) {
      (void)fprintf(stderr, "Could not encode protocol packet.\n");
      return 0;
    }
    sent = send(fd, bytes, packet_size, 0);
    if (sent != (ssize_t)packet_size) {
      (void)fprintf(stderr, "Could not send packet to relay: %s\n",
                    sent < 0 ? strerror(errno) : "short UDP datagram");
      return 0;
    }
  }
  return 1;
}

static int receive_packets(int fd, FILE **output, gbn_receiver *receiver)
{
  unsigned char bytes[PACKET_MAX_SIZE + 1U];
  transfer_packet packet;
  gbn_actions actions;

  for (;;) {
    int64_t now = monotonic_milliseconds();
    int ready;
    ssize_t received;

    if (now < 0) {
      (void)fprintf(stderr, "Could not read monotonic clock: %s\n",
                    strerror(errno));
      return 0;
    }
    if (receiver->phase == GBN_RECEIVER_ACTIVE &&
        now >= receiver->idle_deadline_ms) {
      gbn_receiver_on_timeout(receiver, now, &actions);
      (void)fprintf(stderr, "Receiver timed out waiting for valid packets.\n");
      return 0;
    }
    if (receiver->phase == GBN_RECEIVER_COMPLETED) {
      return 1;
    }
    if (receiver->phase == GBN_RECEIVER_FAILED) {
      (void)fprintf(stderr, "Receiver state machine failed.\n");
      return 0;
    }
    {
      int64_t deadline = receiver->phase == GBN_RECEIVER_ACTIVE
                             ? receiver->idle_deadline_ms
                             : receiver->linger_deadline_ms;
      int64_t remaining = deadline - now;
      ready = wait_readable(fd, remaining > (int64_t)INT_MAX
                                    ? INT_MAX
                                    : (int)remaining);
    }
    if (ready < 0) {
      (void)fprintf(stderr, "Network error while receiving packet: %s\n",
                    strerror(errno));
      return 0;
    }
    if (ready == 0) {
      now = monotonic_milliseconds();
      if (now < 0) {
        (void)fprintf(stderr, "Could not read monotonic clock: %s\n",
                      strerror(errno));
        return 0;
      }
      gbn_receiver_on_timeout(receiver, now, &actions);
      if (actions.failed) {
        (void)fprintf(stderr, "Receiver timed out waiting for valid packets.\n");
        return 0;
      }
      if (actions.completed) {
        return 1;
      }
      continue;
    }

    received = recv(fd, bytes, sizeof(bytes), 0);
    if (received < 0) {
      if (errno == EINTR) {
        continue;
      }
      (void)fprintf(stderr, "Network error while receiving packet: %s\n",
                    strerror(errno));
      return 0;
    }
    if ((size_t)received > PACKET_MAX_SIZE ||
        !packet_decode(bytes, (size_t)received, &packet)) {
      continue;
    }
    now = monotonic_milliseconds();
    if (now < 0) {
      (void)fprintf(stderr, "Could not read monotonic clock: %s\n",
                    strerror(errno));
      return 0;
    }

    gbn_receiver_on_packet(receiver, &packet, now, &actions);
    if (actions.deliver_payload && actions.payload_length > 0U &&
        fwrite(actions.payload, 1U, actions.payload_length, *output) !=
            (size_t)actions.payload_length) {
      (void)fprintf(stderr, "Could not write received file: %s\n",
                    strerror(errno));
      return 0;
    }
    if (actions.finish_output) {
      if (fclose(*output) != 0) {
        *output = NULL;
        (void)fprintf(stderr, "Could not close received file: %s\n",
                      strerror(errno));
        return 0;
      }
      *output = NULL;
    }
    if (!send_protocol_packets(fd, &actions)) {
      return 0;
    }
  }
}

static int register_sender(int fd, const cli_options *options)
{
  char hello[160];
  char reply[256];
  int hello_length;
  int attempt;

  hello_length = snprintf(hello, sizeof(hello),
                          "HELLO %s send %.17f %.17f %.17f",
                          options->session, options->loss, options->corrupt,
                          options->duplicate);
  if (hello_length < 0 || (size_t)hello_length >= sizeof(hello)) {
    (void)fprintf(stderr, "Could not construct sender registration.\n");
    return 0;
  }

  for (attempt = 0; attempt < REGISTRATION_ATTEMPTS; ++attempt) {
    int ready;
    ssize_t sent = send(fd, hello, (size_t)hello_length, 0);
    if (sent != hello_length) {
      (void)fprintf(stderr, "Could not send registration to relay: %s\n",
                    sent < 0 ? strerror(errno) : "short UDP datagram");
      return 0;
    }

    ready = wait_readable(fd, REGISTRATION_TIMEOUT_MS);
    if (ready < 0) {
      (void)fprintf(stderr, "Error waiting for relay registration: %s\n",
                    strerror(errno));
      return 0;
    }
    if (ready == 0) {
      continue;
    }

    {
      ssize_t received = recv(fd, reply, sizeof(reply) - 1U, 0);
      if (received < 0) {
        if (errno == EINTR) {
          --attempt;
          continue;
        }
        (void)fprintf(stderr, "Could not receive relay registration: %s\n",
                      strerror(errno));
        return 0;
      }
      reply[received] = '\0';
      if (received == 2 && memcmp(reply, "OK", 2U) == 0) {
        return 1;
      }
      if (received >= 4 && memcmp(reply, "ERR ", 4U) == 0) {
        (void)fprintf(stderr, "Relay refused registration: %s\n", reply + 4);
        return 0;
      }
      (void)fprintf(stderr, "Unexpected relay registration reply: %s\n", reply);
      return 0;
    }
  }

  (void)fprintf(stderr, "Relay registration timed out after %d attempts.\n",
                REGISTRATION_ATTEMPTS);
  return 0;
}

static int load_packets(const char *path, packet_list *list)
{
  FILE *input;
  file_packets_result result;

  memset(list, 0, sizeof(*list));
  input = fopen(path, "rb");
  if (input == NULL) {
    (void)fprintf(stderr, "Could not open input file '%s': %s\n",
                  path, strerror(errno));
    return 0;
  }

  result = file_packets_read(input, &list->packets, &list->count);
  if (fclose(input) != 0) {
    (void)fprintf(stderr, "Could not close input file '%s': %s\n",
                  path, strerror(errno));
    free(list->packets);
    memset(list, 0, sizeof(*list));
    return 0;
  }
  if (result != FILE_PACKETS_OK) {
    if (result == FILE_PACKETS_TOO_LARGE) {
      (void)fprintf(stderr, "Input file exceeds the 16 MiB transfer limit.\n");
    } else if (result == FILE_PACKETS_NO_MEMORY) {
      (void)fprintf(stderr, "Could not allocate packet buffer.\n");
    } else {
      (void)fprintf(stderr, "Could not read input file '%s'.\n", path);
    }
    free(list->packets);
    memset(list, 0, sizeof(*list));
    return 0;
  }
  return 1;
}

int send_transfer(const cli_options *options)
{
  packet_list packets;
  gbn_sender sender;
  gbn_actions actions;
  int fd = -1;
  int64_t now;
  int success = 0;

  if (!load_packets(options->file, &packets)) {
    return 2;
  }
  if (!gbn_sender_init(&sender, packets.packets,
                       (uint32_t)packets.count, options->window,
                       (int64_t)options->timeout_ms)) {
    (void)fprintf(stderr, "Could not initialize sender state machine.\n");
    free(packets.packets);
    return 2;
  }

  fd = open_relay_socket(options);
  if (fd < 0) {
    free(packets.packets);
    return 2;
  }
  if (!register_sender(fd, options)) {
    (void)close(fd);
    free(packets.packets);
    return 2;
  }

  now = monotonic_milliseconds();
  if (now < 0) {
    (void)fprintf(stderr, "Could not read monotonic clock: %s\n",
                  strerror(errno));
    goto done;
  }
  gbn_sender_start(&sender, now, &actions);
  if (!send_protocol_packets(fd, &actions)) {
    goto done;
  }

  while (!sender.completed && !sender.failed) {
    int ready;
    now = monotonic_milliseconds();
    if (now < 0) {
      (void)fprintf(stderr, "Could not read monotonic clock: %s\n",
                    strerror(errno));
      goto done;
    }
    if (now >= sender.timer_deadline_ms) {
      gbn_sender_on_timeout(&sender, now, &actions);
      if (actions.failed) {
        (void)fprintf(stderr,
                      "Transfer failed after 10 consecutive timeouts without "
                      "ACK progress.\n");
        goto done;
      }
      if (!send_protocol_packets(fd, &actions)) {
        goto done;
      }
      continue;
    }

    {
      int64_t remaining = sender.timer_deadline_ms - now;
      ready = wait_readable(fd, remaining > (int64_t)INT_MAX
                                    ? INT_MAX
                                    : (int)remaining);
    }
    if (ready < 0) {
      (void)fprintf(stderr, "Network error while waiting for ACK: %s\n",
                    strerror(errno));
      goto done;
    }
    if (ready == 0) {
      continue;
    }

    {
      unsigned char bytes[PACKET_MAX_SIZE + 1U];
      transfer_packet ack;
      ssize_t received = recv(fd, bytes, sizeof(bytes), 0);

      if (received < 0) {
        if (errno == EINTR) {
          continue;
        }
        (void)fprintf(stderr, "Network error while receiving ACK: %s\n",
                      strerror(errno));
        goto done;
      }
      if ((size_t)received > PACKET_MAX_SIZE ||
          !packet_decode(bytes, (size_t)received, &ack) ||
          ack.type != PACKET_ACK) {
        continue;
      }
      now = monotonic_milliseconds();
      if (now < 0) {
        (void)fprintf(stderr, "Could not read monotonic clock: %s\n",
                      strerror(errno));
        goto done;
      }
      gbn_sender_on_ack(&sender, &ack, now, &actions);
      if (!send_protocol_packets(fd, &actions)) {
        goto done;
      }
    }
  }
  success = sender.completed;

done:
  if (close(fd) != 0) {
    (void)fprintf(stderr, "Could not close relay socket: %s\n",
                  strerror(errno));
    success = 0;
  }
  free(packets.packets);
  return success ? 0 : 2;
}

int receive_transfer(const cli_options *options)
{
  FILE *output;
  int fd;
  int64_t now;
  gbn_receiver receiver;
  int success;

  output = fopen(options->file, "wb");
  if (output == NULL) {
    (void)fprintf(stderr, "Could not open output file '%s': %s\n",
                  options->file, strerror(errno));
    return 2;
  }

  fd = open_relay_socket(options);
  if (fd < 0) {
    (void)fclose(output);
    return 2;
  }
  if (!register_receiver(fd, options->session)) {
    (void)close(fd);
    (void)fclose(output);
    return 2;
  }

  now = monotonic_milliseconds();
  if (now < 0) {
    (void)fprintf(stderr, "Could not read monotonic clock: %s\n",
                  strerror(errno));
    (void)close(fd);
    (void)fclose(output);
    return 2;
  }
  gbn_receiver_init(&receiver, now);
  success = receive_packets(fd, &output, &receiver);
  if (output != NULL && fclose(output) != 0) {
    (void)fprintf(stderr, "Could not close received file: %s\n",
                  strerror(errno));
    success = 0;
  }
  if (close(fd) != 0) {
    (void)fprintf(stderr, "Could not close relay socket: %s\n",
                  strerror(errno));
    success = 0;
  }
  return success ? 0 : 2;
}
