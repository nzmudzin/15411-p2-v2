/**
 * Copyright (C) 2022 Carnegie Mellon University
 *
 * This file is part of the TCP in the Wild course project developed for the
 * Computer Networks course (15-441/641) taught at Carnegie Mellon University.
 *
 * No part of the project may be copied and/or distributed without the express
 * permission of the 15-441/641 course staff.
 *
 *
 * This file implements the CMU-TCP backend. The backend runs in a different
 * thread and handles all the socket operations separately from the application.
 *
 * This is where most of your code should go. Feel free to modify any function
 * in this file.
 */

#include "backend.h"

#include <poll.h>
#include <time.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>

#include "cmu_packet.h"
#include "cmu_tcp.h"

#define MIN(X, Y) (((X) < (Y)) ? (X) : (Y))
#define TIME_WAIT_LINGER_MS (2 * DEFAULT_TIMEOUT)

/**
 * Tells if a given sequence number has been acknowledged by the socket.
 *
 * @param sock The socket to check for acknowledgements.
 * @param seq Sequence number to check.
 *
 * @return 1 if the sequence number has been acknowledged, 0 otherwise.
 */
int has_been_acked(cmu_socket_t *sock, uint32_t seq) {
  int result;
  result = after(sock->window.last_ack_received, seq);
  return result;
}

static int64_t now_ms(void) {
  struct timespec ts;
  clock_gettime(CLOCK_MONOTONIC, &ts);
  return (int64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

static void send_bare_ack(cmu_socket_t *sock, uint32_t ack) {
  socklen_t conn_len = sizeof(sock->conn);
  uint32_t seq_out = sock->window.last_ack_received;
  uint16_t hlen = sizeof(cmu_tcp_header_t);
  uint16_t plen = hlen;

  uint8_t *response_packet = create_packet(
      sock->my_port, ntohs(sock->conn.sin_port), seq_out, ack, hlen, plen,
      ACK_FLAG_MASK, 1, 0, NULL, NULL, 0);
  sendto(sock->socket, response_packet, plen, 0,
        (struct sockaddr *)&(sock->conn), conn_len);
  free(response_packet);
}

/**
 * Updates the socket information to represent the newly received packet.
 *
 * In the current stop-and-wait implementation, this function also sends an
 * acknowledgement for the packet.
 *
 * @param sock The socket used for handling packets received.
 * @param pkt The packet data received by the socket.
 */
void handle_message(cmu_socket_t *sock, uint8_t *pkt) {
  cmu_tcp_header_t *hdr = (cmu_tcp_header_t *)pkt;
  uint8_t flags = get_flags(hdr);
  uint16_t payload_len = get_payload_len(pkt);
  uint32_t seq = get_seq(hdr);

  if (flags & ACK_FLAG_MASK) {
    uint32_t ack = get_ack(hdr);
    if (after(ack, sock->window.last_ack_received)) {
      sock->window.last_ack_received = ack;
    }

    // Does this ack satisfy a FIN we sent?
    if ((sock->state == FIN_WAIT_1 || sock->state == CLOSING ||
         sock->state == LAST_ACK) &&
        ack == sock->fin_seq + 1) {
      if (sock->state == FIN_WAIT_1 && (flags & FIN_FLAG_MASK)) {
        // Combined FIN+ACK: direct arc, skip FIN_WAIT_2/CLOSING entirely.
        if (seq == sock->window.next_seq_expected) {
          sock->window.next_seq_expected = seq + 1;
        }
        send_bare_ack(sock, sock->window.next_seq_expected);
        sock->state = TIME_WAIT;
        sock->time_wait_deadline_ms = now_ms() + TIME_WAIT_LINGER_MS;
        return;
      }
      if (sock->state == FIN_WAIT_1) {
        sock->state = FIN_WAIT_2;
      } else if (sock->state == CLOSING) {
        sock->state = TIME_WAIT;
        sock->time_wait_deadline_ms = now_ms() + TIME_WAIT_LINGER_MS;
        return;
      } else {  // LAST_ACK
        sock->state = CLOSED;
        return;
      }
    }
  }

  if (flags & FIN_FLAG_MASK) {
    if (seq == sock->window.next_seq_expected) {
      // Buffer any data piggybacked on the FIN, then consume the FIN's own
      // sequence number slot.
      if (payload_len > 0) {
        uint8_t *payload = get_payload(pkt);
        sock->received_buf =
            realloc(sock->received_buf, sock->received_len + payload_len);
        memcpy(sock->received_buf + sock->received_len, payload, payload_len);
        sock->received_len += payload_len;
      }
      sock->window.next_seq_expected = seq + payload_len + 1;
    }
    send_bare_ack(sock, sock->window.next_seq_expected);

    switch (sock->state) {
      case ESTABLISHED:
        sock->state = CLOSE_WAIT;
        break;
      case FIN_WAIT_1:
        sock->state = CLOSING;
        break;
      case FIN_WAIT_2:
        sock->state = TIME_WAIT;
        sock->time_wait_deadline_ms = now_ms() + TIME_WAIT_LINGER_MS;
        break;
      case TIME_WAIT:
        sock->time_wait_deadline_ms = now_ms() + TIME_WAIT_LINGER_MS;
        break;
      default:
        break;  // CLOSE_WAIT / LAST_ACK: duplicate FIN, already re-ack'd above
    }
    return;
  }

  if (payload_len == 0) {
    return;  // Pure ACK, nothing more to do.
  }

  // Ordinary data handling (unchanged from before) — reached regardless of
  // state, so CLOSE_WAIT can still receive data.
  if (seq == sock->window.next_seq_expected) {
    uint8_t *payload = get_payload(pkt);
    sock->received_buf =
        realloc(sock->received_buf, sock->received_len + payload_len);
    memcpy(sock->received_buf + sock->received_len, payload, payload_len);
    sock->received_len += payload_len;
    sock->window.next_seq_expected += payload_len;
  }

  send_bare_ack(sock, sock->window.next_seq_expected);
}

/**
 * Checks if the socket received any data.
 *
 * It first peeks at the header to figure out the length of the packet and then
 * reads the entire packet.
 *
 * @param sock The socket used for receiving data on the connection.
 * @param flags Flags that determine how the socket should wait for data. Check
 *             `cmu_read_mode_t` for more information.
 */
void check_for_data(cmu_socket_t *sock, cmu_read_mode_t flags) {
  cmu_tcp_header_t hdr;
  uint8_t *pkt;
  socklen_t conn_len = sizeof(sock->conn);
  ssize_t len = 0;
  uint32_t plen = 0, buf_size = 0, n = 0;

  while (pthread_mutex_lock(&(sock->recv_lock)) != 0) {
  }
  switch (flags) {
    case NO_FLAG:
      len = recvfrom(sock->socket, &hdr, sizeof(cmu_tcp_header_t), MSG_PEEK,
                     (struct sockaddr *)&(sock->conn), &conn_len);
      break;
    case TIMEOUT: {
      // Using `poll` here so that we can specify a timeout.
      struct pollfd ack_fd;
      ack_fd.fd = sock->socket;
      ack_fd.events = POLLIN;
      // Timeout after DEFAULT_TIMEOUT.
      if (poll(&ack_fd, 1, DEFAULT_TIMEOUT) <= 0) {
        break;
      }
    }
    // Fallthrough.
    case NO_WAIT:
      len = recvfrom(sock->socket, &hdr, sizeof(cmu_tcp_header_t),
                     MSG_DONTWAIT | MSG_PEEK, (struct sockaddr *)&(sock->conn),
                     &conn_len);
      break;
    default:
      perror("ERROR unknown flag");
  }
  if (len >= (ssize_t)sizeof(cmu_tcp_header_t)) {
    plen = get_plen(&hdr);
    pkt = malloc(plen);
    while (buf_size < plen) {
      n = recvfrom(sock->socket, pkt + buf_size, plen - buf_size, 0,
                   (struct sockaddr *)&(sock->conn), &conn_len);
      buf_size = buf_size + n;
    }
    handle_message(sock, pkt);
    free(pkt);
  }
  pthread_mutex_unlock(&(sock->recv_lock));
}

/**
 * Waits up to `timeout_ms` for a single raw packet to arrive and returns it
 * unmodified (does not route it through handle_message()). Used only during
 * the handshake, before the socket is ESTABLISHED and before the normal
 * data/ACK pipeline applies.
 *
 * @param sock The socket to receive on.
 * @param timeout_ms Milliseconds to wait, or a negative value to block
 *                   indefinitely.
 *
 * @return A malloc'd packet buffer (caller must free), or NULL if the
 *         timeout elapsed with nothing arriving.
 */
static uint8_t *recv_packet_timeout(cmu_socket_t *sock, int timeout_ms) {
  struct pollfd pfd;
  pfd.fd = sock->socket;
  pfd.events = POLLIN;

  if (poll(&pfd, 1, timeout_ms) <= 0) {
    return NULL;
  }

  cmu_tcp_header_t hdr;
  socklen_t conn_len = sizeof(sock->conn);
  ssize_t len =
      recvfrom(sock->socket, &hdr, sizeof(cmu_tcp_header_t),
               MSG_DONTWAIT | MSG_PEEK, (struct sockaddr *)&(sock->conn),
               &conn_len);
  if (len < (ssize_t)sizeof(cmu_tcp_header_t)) {
    return NULL;
  }

  uint16_t plen = get_plen(&hdr);
  uint8_t *pkt = malloc(plen);
  uint32_t buf_size = 0;
  while (buf_size < plen) {
    ssize_t n = recvfrom(sock->socket, pkt + buf_size, plen - buf_size, 0,
                        (struct sockaddr *)&(sock->conn), &conn_len);
    buf_size += (uint32_t)n;
  }
  return pkt;
}

/**
 * Builds a header-only control packet (SYN / SYN-ACK / ACK) with no payload.
 */
static uint8_t *make_control_packet(cmu_socket_t *sock, uint32_t seq,
                                    uint32_t ack, uint8_t flags) {
  uint16_t src = sock->my_port;
  uint16_t dst = ntohs(sock->conn.sin_port);
  uint16_t hlen = sizeof(cmu_tcp_header_t);
  uint16_t plen = hlen;
  uint16_t adv_window = 1;  // CP1 window handling comes next; placeholder.

  return create_packet(src, dst, seq, ack, hlen, plen, flags, adv_window, 0,
                       NULL, NULL, 0);
}

/**
 * Runs the active-open (client) side of the three-way handshake.
 */
static void handshake_initiator(cmu_socket_t *sock) {
  socklen_t conn_len = sizeof(sock->conn);
  uint32_t isn = sock->window.last_ack_received;  // Set in cmu_socket().

  sock->state = SYN_SENT;

  uint8_t *syn_pkt = make_control_packet(sock, isn, 0, SYN_FLAG_MASK);
  uint16_t syn_plen = get_plen((cmu_tcp_header_t *)syn_pkt);

  while (1) {
    sendto(sock->socket, syn_pkt, syn_plen, 0, (struct sockaddr *)&(sock->conn),
          conn_len);

    uint8_t *pkt = recv_packet_timeout(sock, DEFAULT_TIMEOUT);
    if (pkt == NULL) {
      continue;  // Timed out: resend the SYN.
    }

    cmu_tcp_header_t *hdr = (cmu_tcp_header_t *)pkt;
    uint8_t flags = get_flags(hdr);

    if ((flags & (SYN_FLAG_MASK | ACK_FLAG_MASK)) ==
            (SYN_FLAG_MASK | ACK_FLAG_MASK) &&
        get_ack(hdr) == isn + 1) {
      sock->window.next_seq_expected = get_seq(hdr) + 1;
      sock->window.last_ack_received = isn + 1;
      free(pkt);
      break;
    }
    free(pkt);  // Not the SYN-ACK we wanted; keep waiting/resending.
  }
  free(syn_pkt);

  uint8_t *ack_pkt = make_control_packet(
      sock, sock->window.last_ack_received, sock->window.next_seq_expected,
      ACK_FLAG_MASK);
  sendto(sock->socket, ack_pkt, get_plen((cmu_tcp_header_t *)ack_pkt), 0,
        (struct sockaddr *)&(sock->conn), conn_len);
  free(ack_pkt);

  sock->state = ESTABLISHED;
}

/**
 * Runs the passive-open (server) side of the three-way handshake.
 */
static void handshake_listener(cmu_socket_t *sock) {
  socklen_t conn_len = sizeof(sock->conn);

  // Block until the initial SYN arrives.
  uint32_t peer_isn = 0;
  while (1) {
    uint8_t *pkt = recv_packet_timeout(sock, -1);  // -1 = wait forever.
    if (pkt == NULL) {
      continue;
    }
    cmu_tcp_header_t *hdr = (cmu_tcp_header_t *)pkt;
    if (get_flags(hdr) == SYN_FLAG_MASK) {
      peer_isn = get_seq(hdr);
      free(pkt);
      break;
    }
    free(pkt);  // Ignore anything that isn't a plain SYN.
  }

  sock->window.next_seq_expected = peer_isn + 1;
  uint32_t my_isn = sock->window.last_ack_received;  // Set in cmu_socket().
  sock->state = SYN_RECEIVED;

  uint8_t *synack_pkt = make_control_packet(
      sock, my_isn, sock->window.next_seq_expected,
      SYN_FLAG_MASK | ACK_FLAG_MASK);
  uint16_t synack_plen = get_plen((cmu_tcp_header_t *)synack_pkt);

  while (1) {
    sendto(sock->socket, synack_pkt, synack_plen, 0,
          (struct sockaddr *)&(sock->conn), conn_len);

    uint8_t *pkt = recv_packet_timeout(sock, DEFAULT_TIMEOUT);
    if (pkt == NULL) {
      continue;  // Timed out: resend the SYN-ACK.
    }

    cmu_tcp_header_t *hdr = (cmu_tcp_header_t *)pkt;
    if (get_flags(hdr) == ACK_FLAG_MASK && get_ack(hdr) == my_isn + 1) {
      free(pkt);
      break;
    }
    free(pkt);  // Not the final ACK; keep waiting/resending.
  }
  free(synack_pkt);

  sock->window.last_ack_received = my_isn + 1;
  sock->state = ESTABLISHED;
}

/**
 * Performs the TCP three-way handshake, dispatching based on socket type.
 * Must be called once, before begin_backend()'s main loop starts sending or
 * receiving data.
 */
static void handshake(cmu_socket_t *sock) {
  switch (sock->type) {
    case TCP_INITIATOR:
      handshake_initiator(sock);
      break;
    case TCP_LISTENER:
      handshake_listener(sock);
      break;
    default:
      perror("ERROR unknown socket type in handshake");
  }
}

static void send_data_segment(cmu_socket_t *sock, uint8_t *payload,
                              uint32_t seq, uint16_t payload_len) {
  socklen_t conn_len = sizeof(sock->conn);
  uint32_t ack = sock->window.next_seq_expected;
  uint16_t hlen = sizeof(cmu_tcp_header_t);
  uint16_t plen = hlen + payload_len;

  uint8_t *pkt = create_packet(sock->my_port, ntohs(sock->conn.sin_port), seq,
                               ack, hlen, plen, ACK_FLAG_MASK, 1, 0, NULL, payload,
                               payload_len);
  sendto(sock->socket, pkt, plen, 0, (struct sockaddr *)&(sock->conn),
        conn_len);
  free(pkt);
}

static void send_fin(cmu_socket_t *sock) {
  socklen_t conn_len = sizeof(sock->conn);
  uint16_t hlen = sizeof(cmu_tcp_header_t);
  uint16_t plen = hlen;

  uint8_t *pkt = create_packet(
      sock->my_port, ntohs(sock->conn.sin_port), sock->fin_seq,
      sock->window.next_seq_expected, hlen, plen,
      FIN_FLAG_MASK | ACK_FLAG_MASK, 1, 0, NULL, NULL, 0);
  sendto(sock->socket, pkt, plen, 0, (struct sockaddr *)&(sock->conn),
        conn_len);
  free(pkt);
}

/**
 * Drives our side's active close. Handles both "we close first"
 * (ESTABLISHED -> FIN_WAIT_1 -> ...) and "peer already closed, now we close
 * too" (CLOSE_WAIT -> LAST_ACK -> CLOSED). All the reactive state
 * transitions happen inside handle_message(), called via check_for_data();
 * this function just sends/resends the FIN and waits for things to settle.
 */
static void teardown_active(cmu_socket_t *sock) {
  sock->fin_seq = sock->window.last_ack_received;
  send_fin(sock);
  sock->state = (sock->state == CLOSE_WAIT) ? LAST_ACK : FIN_WAIT_1;

  while (sock->state != TIME_WAIT && sock->state != CLOSED) {
    cmu_socket_state_t prev_state = sock->state;
    check_for_data(sock, TIMEOUT);
    if (sock->state == prev_state) {
      send_fin(sock);  // Timed out with no progress: resend.
    }
  }

  if (sock->state == CLOSED) {
    return;  // LAST_ACK path: no TIME_WAIT needed.
  }

  while (now_ms() < sock->time_wait_deadline_ms) {
    check_for_data(sock, TIMEOUT);  // Re-acks any retransmitted FIN, which
                                     // also pushes time_wait_deadline_ms out.
  }
  sock->state = CLOSED;
}

/**
 * Sends buf_len bytes using a fixed-size Go-Back-N window (CP1_WINDOW_SIZE
 * bytes). Blocks until everything has been sent and cumulatively ACKed.
 *
 * left/right are byte offsets into `data`: left = oldest unacked byte,
 * right = next byte not yet sent. The single logical retransmit timer
 * belongs to the packet at `left`; we detect it firing by noticing that
 * check_for_data(sock, TIMEOUT) came back without last_ack_received moving.
 */
void window_send(cmu_socket_t *sock, uint8_t *data, int buf_len) {
  uint32_t base_seq = sock->window.last_ack_received;  // seq of data[0]
  int left = 0;
  int right = 0;

  while (left < buf_len) {
    while (right < buf_len && (right - left) < CP1_WINDOW_SIZE) {
      uint16_t payload_len = MIN((uint32_t)(buf_len - right), (uint32_t)MSS);
      send_data_segment(sock, data + right, base_seq + right, payload_len);
      right += payload_len;
    }

    uint32_t acked_before = sock->window.last_ack_received;
    check_for_data(sock, TIMEOUT);
    uint32_t acked_now = sock->window.last_ack_received;

    if (after(acked_now, acked_before)) {
      left += (int)(acked_now - (base_seq + left));
    } else {
      // Timed out with no progress: Go-Back-N, resend the whole window.
      int resend = left;
      while (resend < right) {
        uint16_t payload_len = MIN((uint32_t)(right - resend), (uint32_t)MSS);
        send_data_segment(sock, data + resend, base_seq + resend, payload_len);
        resend += payload_len;
      }
    }
  }
}

void *begin_backend(void *in) {
  cmu_socket_t *sock = (cmu_socket_t *)in;
  int death, buf_len, send_signal;
  uint8_t *data;

  handshake(sock);

  while (1) {
    while (pthread_mutex_lock(&(sock->death_lock)) != 0) {
    }
    death = sock->dying;
    pthread_mutex_unlock(&(sock->death_lock));

    while (pthread_mutex_lock(&(sock->send_lock)) != 0) {
    }
    buf_len = sock->sending_len;

    if (death && buf_len == 0) {
      pthread_mutex_unlock(&(sock->send_lock));  // was previously left locked
      teardown_active(sock);
      break;
    }

    if (buf_len > 0) {
      data = malloc(buf_len);
      memcpy(data, sock->sending_buf, buf_len);
      sock->sending_len = 0;
      free(sock->sending_buf);
      sock->sending_buf = NULL;
      pthread_mutex_unlock(&(sock->send_lock));
      window_send(sock, data, buf_len);
      free(data);
    } else {
      pthread_mutex_unlock(&(sock->send_lock));
    }

    check_for_data(sock, NO_WAIT);

    while (pthread_mutex_lock(&(sock->recv_lock)) != 0) {
    }

    send_signal = sock->received_len > 0;

    pthread_mutex_unlock(&(sock->recv_lock));

    if (send_signal) {
      pthread_cond_signal(&(sock->wait_cond));
    }
  }

  pthread_exit(NULL);
  return NULL;
}
