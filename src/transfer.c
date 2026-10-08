#define _POSIX_C_SOURCE 200809L

#include "transfer.h"

#include "packet.h"

#include <errno.h>
#include <poll.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#define REGISTRATION_ATTEMPTS 5
#define REGISTRATION_TIMEOUT_MS 1000
#define RECEIVE_TIMEOUT_MS 30000
#define FIN_LINGER_MS 2000

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

  descriptor.fd = fd;
  descriptor.events = POLLIN;
  descriptor.revents = 0;
  do {
    result = poll(&descriptor, 1U, timeout_ms);
  } while (result < 0 && errno == EINTR);
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

static int send_ack(int fd, uint32_t expected)
{
  transfer_packet ack;
  unsigned char bytes[PACKET_MAX_SIZE];
  size_t packet_size;
  ssize_t sent;

  memset(&ack, 0, sizeof(ack));
  ack.type = PACKET_ACK;
  ack.seq = expected;
  if (!packet_encode(&ack, bytes, sizeof(bytes), &packet_size)) {
    (void)fprintf(stderr, "Could not encode ACK packet.\n");
    return 0;
  }
  sent = send(fd, bytes, packet_size, 0);
  if (sent != (ssize_t)packet_size) {
    (void)fprintf(stderr, "Could not send ACK to relay: %s\n",
                  sent < 0 ? strerror(errno) : "short UDP datagram");
    return 0;
  }
  return 1;
}

static int receive_until_fin(int fd, FILE **output, uint32_t *final_ack,
                             uint32_t *fin_sequence)
{
  unsigned char bytes[PACKET_MAX_SIZE + 1U];
  transfer_packet packet;
  int64_t last_valid;

  last_valid = monotonic_milliseconds();
  if (last_valid < 0) {
    (void)fprintf(stderr, "Could not read monotonic clock: %s\n",
                  strerror(errno));
    return 0;
  }

  for (;;) {
    int64_t now = monotonic_milliseconds();
    int64_t remaining;
    int ready;
    ssize_t received;

    if (now < 0) {
      (void)fprintf(stderr, "Could not read monotonic clock: %s\n",
                    strerror(errno));
      return 0;
    }
    remaining = (int64_t)RECEIVE_TIMEOUT_MS - (now - last_valid);
    if (remaining <= 0) {
      (void)fprintf(stderr, "Receiver timed out waiting for valid packets.\n");
      return 0;
    }
    ready = wait_readable(fd, (int)remaining);
    if (ready < 0) {
      (void)fprintf(stderr, "Network error while receiving packet: %s\n",
                    strerror(errno));
      return 0;
    }
    if (ready == 0) {
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
    last_valid = monotonic_milliseconds();
    if (last_valid < 0) {
      (void)fprintf(stderr, "Could not read monotonic clock: %s\n",
                    strerror(errno));
      return 0;
    }

    if (packet.type == PACKET_DATA) {
      if (packet.seq == *final_ack) {
        if (packet.length > 0U &&
            fwrite(packet.payload, 1U, packet.length, *output) !=
                (size_t)packet.length) {
          (void)fprintf(stderr, "Could not write received file: %s\n",
                        strerror(errno));
          return 0;
        }
        ++(*final_ack);
      }
      if (!send_ack(fd, *final_ack)) {
        return 0;
      }
    } else if (packet.type == PACKET_FIN) {
      if (packet.seq == *final_ack) {
        *fin_sequence = packet.seq;
        ++(*final_ack);
        if (fclose(*output) != 0) {
          *output = NULL;
          (void)fprintf(stderr, "Could not close received file: %s\n",
                        strerror(errno));
          return 0;
        }
        *output = NULL;
        return send_ack(fd, *final_ack);
      }
      if (!send_ack(fd, *final_ack)) {
        return 0;
      }
    }
  }
}

static int linger_for_fin(int fd, uint32_t fin_sequence, uint32_t final_ack)
{
  unsigned char bytes[PACKET_MAX_SIZE + 1U];
  transfer_packet packet;
  int64_t now = monotonic_milliseconds();
  int64_t deadline;

  if (now < 0) {
    (void)fprintf(stderr, "Could not read monotonic clock: %s\n",
                  strerror(errno));
    return 0;
  }
  deadline = now + (int64_t)FIN_LINGER_MS;

  while (now < deadline) {
    int64_t remaining = deadline - now;
    int ready = wait_readable(fd, (int)remaining);
    ssize_t received;

    if (ready < 0) {
      (void)fprintf(stderr, "Network error during FIN linger: %s\n",
                    strerror(errno));
      return 0;
    }
    if (ready == 0) {
      return 1;
    }
    received = recv(fd, bytes, sizeof(bytes), 0);
    if (received < 0) {
      if (errno == EINTR) {
        now = monotonic_milliseconds();
        if (now < 0) {
          (void)fprintf(stderr, "Could not read monotonic clock: %s\n",
                        strerror(errno));
          return 0;
        }
        continue;
      }
      (void)fprintf(stderr, "Network error during FIN linger: %s\n",
                    strerror(errno));
      return 0;
    }
    if ((size_t)received <= PACKET_MAX_SIZE &&
        packet_decode(bytes, (size_t)received, &packet) &&
        packet.type == PACKET_FIN && packet.seq == fin_sequence &&
        !send_ack(fd, final_ack)) {
      return 0;
    }
    now = monotonic_milliseconds();
    if (now < 0) {
      (void)fprintf(stderr, "Could not read monotonic clock: %s\n",
                    strerror(errno));
      return 0;
    }
  }
  return 1;
}

int receive_transfer(const cli_options *options)
{
  FILE *output;
  int fd;
  uint32_t expected = 0U;
  uint32_t fin_sequence = 0U;
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

  success = receive_until_fin(fd, &output, &expected, &fin_sequence);
  if (success) {
    success = linger_for_fin(fd, fin_sequence, expected);
  }
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
