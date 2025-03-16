#pragma once

#include "receiver.h"
#include "sender.h"

/********* TYPES *********/

/* TCP connection states for proper handshake tracking */
typedef enum tcp_state {
    TCP_CLOSED,       /* No connection */
    TCP_LISTEN,       /* Waiting for connection */
    TCP_SYN_SENT,     /* Active open, sent SYN */
    TCP_SYN_RECEIVED, /* Passive open, received SYN, sent SYN-ACK */
    TCP_ESTABLISHED,  /* Connection established, handshake complete */
    TCP_FIN_WAIT_1,   /* FIN sent, waiting for ACK */
    TCP_FIN_WAIT_2,   /* FIN sent and ACKed, waiting for remote FIN */
    TCP_CLOSE_WAIT,   /* Remote side has sent FIN, waiting for app to close */
    TCP_CLOSING,      /* Both sides initiated close */
    TCP_LAST_ACK,     /* Local FIN sent after receiving remote FIN */
    TCP_TIME_WAIT     /* Waiting for delayed segments to expire */
} tcp_state_t;

/* TCP peer structure representing a connection endpoint */
typedef struct tcp_peer {
    sender_t sender;     /* Sender component of the connection */
    receiver_t receiver; /* Receiver component of the connection */

    tcp_state_t state;                /* Current TCP connection state */
    uint32_t time_of_last_receipt;    /* Time when last packet was received */
    bool linger_after_streams_finish; /* Whether to linger after streams finish */
} tcp_peer_t;

/********* HELPER FUNCTIONS *********/

/**
 * Convert an RCP datagram to a sender segment
 *
 * @param datagram Pointer to the RCP datagram to convert
 * @return A sender segment structure containing the converted data
 */
sender_segment_t rcp_to_sender_segment(rcp_datagram_t *datagram) {
    assert(datagram);

    sender_segment_t seg = {
        .seqno = datagram->header.seqno,
        .is_syn = rcp_has_flag(&datagram->header, RCP_FLAG_SYN),
        .is_fin = rcp_has_flag(&datagram->header, RCP_FLAG_FIN),
        .len = datagram->header.payload_len,
    };

    /* Copy payload if present */
    if (datagram->payload && datagram->header.payload_len > 0) {
        memcpy(seg.payload, datagram->payload, seg.len);
    }

    return seg;
}

/**
 * Convert an RCP datagram to a receiver segment
 *
 * @param datagram Pointer to the RCP datagram to convert
 * @return A receiver segment structure containing the converted data
 */
receiver_segment_t rcp_to_receiver_segment(rcp_datagram_t *datagram) {
    assert(datagram);

    receiver_segment_t seg = {
        .ackno = datagram->header.ackno,
        .is_ack = rcp_has_flag(&datagram->header, RCP_FLAG_ACK),
        .window_size = datagram->header.window,
    };

    return seg;
}

/**
 * Create an RCP datagram with both SYN and ACK flags
 *
 * @param sender The sender to set up the segment
 * @param receiver The receiver to set up the acknowledgment
 * @param ackno The acknowledgment number to use
 * @return A properly formatted RCP datagram with SYN and ACK flags
 */
rcp_datagram_t create_syn_ack_datagram(sender_t *sender, receiver_t *receiver, uint32_t ackno) {
    assert(sender);
    assert(receiver);

    rcp_datagram_t datagram = rcp_datagram_init();

    /* Set the source and destination addresses */
    datagram.header.src = sender->local_addr;
    datagram.header.dst = sender->remote_addr;

    /* Set SYN and ACK flags */
    rcp_set_flag(&datagram.header, RCP_FLAG_SYN);
    rcp_set_flag(&datagram.header, RCP_FLAG_ACK);

    /* Set the sequence number from the sender */
    datagram.header.seqno = sender->next_seqno;

    /* Set the acknowledgment number */
    datagram.header.ackno = ackno;

    /* Set the window size from the receiver */
    datagram.header.window = receiver->window_size;

    /* Zero out the payload length as SYN-ACK has no payload */
    datagram.header.payload_len = 0;

    /* Compute the checksum */
    rcp_datagram_compute_checksum(&datagram);

    return datagram;
}

/********* TCP PEER *********/

/**
 * Initialize a new TCP peer
 *
 * @param sender_nrf The NRF interface to use for sending segments
 * @param receiver_nrf The NRF interface to use for receiving segments
 * @param local_addr The local RCP address
 * @param remote_addr The remote RCP address
 * @param is_server Whether this peer should act as a server (passive open)
 * @return Initialized TCP peer structure
 */
static inline tcp_peer_t tcp_peer_init(nrf_t *sender_nrf, nrf_t *receiver_nrf, uint8_t local_addr,
                                       uint8_t remote_addr, bool is_server) {
    tcp_peer_t peer;

    peer.sender = sender_init(sender_nrf, local_addr, remote_addr);
    peer.receiver = receiver_init(receiver_nrf, local_addr, remote_addr);

    peer.time_of_last_receipt = timer_get_usec(); /* Initialize to current time */
    peer.linger_after_streams_finish = true;

    /* Set initial state based on role */
    peer.state = is_server ? TCP_LISTEN : TCP_CLOSED;

    return peer;
}

/**
 * Create and send a SYN segment to initiate a connection
 *
 * @param peer The TCP peer initiating the connection
 * @return True if successful, false otherwise
 */
static inline bool tcp_send_syn(tcp_peer_t *peer) {
    assert(peer);

    /* Create a SYN segment with the initial sequence number */
    sender_segment_t syn_seg = {
        .seqno = 0, /* Initial sequence number */
        .is_syn = true,
        .is_fin = false,
        .len = 0 /* SYN has no payload */
    };

    /* Queue the SYN segment for sending */
    sender_send_segment(&peer->sender, syn_seg);
    printk("  [SEND %x] SYN with seqno %u\n", peer->sender.local_addr, syn_seg.seqno);
    peer->state = TCP_SYN_SENT;

    return true;
}

/**
 * Create and send a SYN-ACK segment in response to a SYN
 *
 * @param peer The TCP peer responding to a SYN
 * @param recv_seqno The sequence number received in the SYN
 * @return True if successful, false otherwise
 */
static inline bool tcp_send_syn_ack(tcp_peer_t *peer, uint32_t recv_seqno) {
    assert(peer);

    /* Create the SYN-ACK datagram */
    rcp_datagram_t datagram =
        create_syn_ack_datagram(&peer->sender, &peer->receiver, recv_seqno + 1);

    /* Serialize the datagram */
    uint8_t buffer[RCP_TOTAL_SIZE];
    uint16_t length = rcp_datagram_serialize(&datagram, buffer, RCP_TOTAL_SIZE);

    /* Send the SYN-ACK to the remote peer */
    uint32_t next_hop_nrf = rtable_map[peer->sender.local_addr][peer->sender.remote_addr];
    nrf_send_noack(peer->sender.nrf, next_hop_nrf, buffer, length);

    printk("  [SEND %x] SYN-ACK with seqno %u, ackno %u\n", peer->sender.local_addr,
           peer->sender.next_seqno, recv_seqno + 1);

    /* Update the sender's sequence number */
    peer->sender.next_seqno++;

    /* Create a pending segment for retransmission if needed */
    sender_segment_t syn_ack_seg = {
        .seqno = peer->sender.next_seqno - 1, /* We just incremented */
        .is_syn = true,
        .is_fin = false,
        .len = 0 /* SYN-ACK has no payload */
    };

    /* Add to the retransmission queue */
    unacked_segment_t *pending = kmalloc(sizeof(unacked_segment_t));
    if (pending) {
        memcpy(&pending->seg, &syn_ack_seg, sizeof(sender_segment_t));
        pending->next = NULL;

        if (rtq_empty(&peer->sender.pending_segs)) {
            peer->sender.rto_time_us = timer_get_usec() + peer->sender.initial_RTO_us;
        }

        rtq_push(&peer->sender.pending_segs, pending);
    }

    peer->state = TCP_SYN_RECEIVED;
    return true;
}

/**
 * Send a FIN segment to initiate connection termination
 *
 * @param peer The TCP peer initiating termination
 * @return True if successful, false otherwise
 */
static inline bool tcp_send_fin(tcp_peer_t *peer) {
    assert(peer);

    /* Create a FIN segment */
    sender_segment_t fin_seg = {
        .seqno = peer->sender.next_seqno,
        .is_syn = false,
        .is_fin = true,
        .len = 0 /* FIN has no payload */
    };

    /* Queue the FIN segment for sending */
    sender_send_segment(&peer->sender, fin_seg);
    printk("  [SEND %x] FIN with seqno %u\n", peer->sender.local_addr, fin_seg.seqno);

    /* Update state based on current state */
    if (peer->state == TCP_ESTABLISHED) {
        peer->state = TCP_FIN_WAIT_1;
    } else if (peer->state == TCP_CLOSE_WAIT) {
        peer->state = TCP_LAST_ACK;
    }

    return true;
}

/**
 * Process a received FIN segment
 *
 * @param peer The TCP peer processing the FIN
 * @param segment The received segment with FIN flag
 */
static inline void tcp_process_fin(tcp_peer_t *peer, sender_segment_t *segment) {
    assert(peer);
    assert(segment);

    printk("  [RECV %x] FIN from %u\n", peer->receiver.local_addr, segment->seqno);

    /* Mark receiver as having received FIN */
    peer->receiver.fin_received = true;

    /* Calculate the next expected sequence number (after FIN) */
    uint32_t next_seqno = segment->seqno + segment->len + 1; /* +1 for FIN */

    /* Send an ACK for the FIN */
    receiver_segment_t ack = {
        .ackno = next_seqno, .is_ack = true, .window_size = peer->receiver.window_size};

    sender_send_ack(&peer->sender, &ack);
    printk("  [SEND %x] ACK for FIN with ackno %u\n", peer->sender.local_addr, ack.ackno);

    /* Update state based on current state */
    if (peer->state == TCP_ESTABLISHED) {
        peer->state = TCP_CLOSE_WAIT;
    } else if (peer->state == TCP_FIN_WAIT_1) {
        peer->state = TCP_CLOSING;
    } else if (peer->state == TCP_FIN_WAIT_2) {
        peer->state = TCP_TIME_WAIT;
    }

    /* Close the receiving bytestream */
    bs_end_input(&peer->receiver.writer);
}

/**
 * Process an ACK for a sent FIN
 *
 * @param peer The TCP peer processing the ACK
 * @param ackno The acknowledgment number in the ACK
 */
static inline void tcp_process_fin_ack(tcp_peer_t *peer, uint32_t ackno) {
    assert(peer);

    printk("  [RECV %x] ACK for FIN with ackno %u\n", peer->receiver.local_addr, ackno);

    /* Update state based on current state */
    if (peer->state == TCP_FIN_WAIT_1) {
        peer->state = TCP_FIN_WAIT_2;
    } else if (peer->state == TCP_CLOSING) {
        peer->state = TCP_TIME_WAIT;
    } else if (peer->state == TCP_LAST_ACK) {
        peer->state = TCP_CLOSED;
    }
}

/**
 * Process incoming segments from the remote peer and handle handshake steps
 *
 * @param peer The TCP peer to process
 */
static inline void tcp_check_incoming(tcp_peer_t *peer) {
    assert(peer);

    uint8_t buffer[RCP_TOTAL_SIZE];

    /* Try to receive a packet from NRF with a 1 ms timeout */
    int ret = nrf_read_exact_timeout(peer->receiver.nrf, buffer, RCP_TOTAL_SIZE, 1000);
    if (ret <= 0) {
        return; /* No data or error */
    }

    /* Try to parse the read packet into an RCP datagram */
    rcp_datagram_t datagram = rcp_datagram_init();
    if (rcp_datagram_parse(&datagram, buffer, ret) <= 0) {
        return; /* Parsing failed */
    }

    /* Verify the checksum of the received packet */
    if (!rcp_datagram_verify_checksum(&datagram)) {
        return; /* Invalid checksum */
    }

    /* Update time of last packet receipt */
    peer->time_of_last_receipt = timer_get_usec();

    /* Extract flags for processing */
    bool is_syn = rcp_has_flag(&datagram.header, RCP_FLAG_SYN);
    bool is_ack = rcp_has_flag(&datagram.header, RCP_FLAG_ACK);
    bool is_fin = rcp_has_flag(&datagram.header, RCP_FLAG_FIN);

    /* Process based on the current TCP state */
    switch (peer->state) {
        case TCP_LISTEN:
            /* Server is listening for connections */
            if (is_syn && !is_ack) {
                /* Received SYN: Send SYN-ACK */
                printk("  [RECV %x] SYN from %u\n", peer->receiver.local_addr,
                       datagram.header.seqno);

                /* Set receiver's initial sequence number */
                peer->receiver.syn_received = true;
                peer->receiver.next_seqno = datagram.header.seqno + 1;

                /* Send SYN-ACK */
                tcp_send_syn_ack(peer, datagram.header.seqno);
            }
            break;

        case TCP_SYN_SENT:
            /* Client has sent SYN, waiting for response */
            if (is_syn && is_ack) {
                /* Received SYN-ACK: Send ACK */
                printk("  [RECV %x] SYN-ACK from %u with ackno %u\n", peer->receiver.local_addr,
                       datagram.header.seqno, datagram.header.ackno);

                /* Update sender's acknowledged sequence number */
                peer->sender.acked_seqno = datagram.header.ackno;

                /* Update receiver's sequence number */
                peer->receiver.syn_received = true;
                peer->receiver.next_seqno = datagram.header.seqno + 1;

                /* Send ACK for the SYN-ACK */
                receiver_segment_t ack = {.ackno = datagram.header.seqno + 1,
                                          .is_ack = true,
                                          .window_size = peer->receiver.window_size};

                sender_send_ack(&peer->sender, &ack);
                printk("  [SEND %x] ACK with ackno %u\n", peer->sender.local_addr, ack.ackno);

                /* Connection is now established */
                peer->state = TCP_ESTABLISHED;
                printk("  [INFO] Connection established\n");

                /* Remove SYN from pending segments queue since it was ACKed */
                if (!rtq_empty(&peer->sender.pending_segs)) {
                    unacked_segment_t *seg = rtq_start(&peer->sender.pending_segs);
                    if (seg->seg.is_syn) {
                        rtq_pop(&peer->sender.pending_segs);
                    }
                }
            } else if (is_syn && !is_ack) {
                /* Simultaneous open - received SYN while in SYN_SENT */
                printk("  [RECV %x] SYN from %u (simultaneous open)\n", peer->receiver.local_addr,
                       datagram.header.seqno);

                /* Update receiver's sequence number */
                peer->receiver.next_seqno = datagram.header.seqno + 1;

                /* Send SYN-ACK */
                tcp_send_syn_ack(peer, datagram.header.seqno);
            }
            break;

        case TCP_SYN_RECEIVED:
            /* Server has sent SYN-ACK, waiting for ACK */
            if (is_ack && !is_syn) {
                /* Received ACK for SYN-ACK: Connection established */
                printk("  [RECV %x] ACK with ackno %u\n", peer->receiver.local_addr,
                       datagram.header.ackno);

                /* Process the ACK */
                receiver_segment_t ack_segment = rcp_to_receiver_segment(&datagram);
                sender_process_reply(&peer->sender, &ack_segment);

                /* Connection is now established */
                peer->state = TCP_ESTABLISHED;
                printk("  [INFO] Connection established\n");
            }
            break;

        case TCP_ESTABLISHED:
            /* Connection is established, handle normal data flow and termination */
            if (is_fin) {
                /* Process FIN segment */
                sender_segment_t fin_segment = rcp_to_sender_segment(&datagram);
                tcp_process_fin(peer, &fin_segment);
            } else if (is_ack) {
                /* Process ACK */
                receiver_segment_t ack_segment = rcp_to_receiver_segment(&datagram);
                printk("  [RECV %x] ACK from %u with window size %u\n", peer->receiver.local_addr,
                       ack_segment.ackno, ack_segment.window_size);
                sender_process_reply(&peer->sender, &ack_segment);
            }

            /* Process data segment if present */
            if (datagram.header.payload_len > 0) {
                sender_segment_t data_segment = rcp_to_sender_segment(&datagram);
                printk("  [RECV %x] segment from %u to %u with length %u\n",
                       peer->receiver.local_addr, data_segment.seqno,
                       data_segment.seqno + data_segment.len, data_segment.len);
                recv_process_segment(&peer->receiver, &data_segment);
            }
            break;

        case TCP_FIN_WAIT_1:
            /* We've sent FIN, waiting for ACK and maybe FIN */
            if (is_fin) {
                /* Process FIN segment (could be simultaneous close) */
                sender_segment_t fin_segment = rcp_to_sender_segment(&datagram);
                tcp_process_fin(peer, &fin_segment);
            }

            if (is_ack) {
                /* Process ACK - could be ACK for our FIN */
                receiver_segment_t ack_segment = rcp_to_receiver_segment(&datagram);

                /* Check if this ACK is for our FIN */
                if (ack_segment.ackno == peer->sender.next_seqno) {
                    printk("  [RECV %x] FIN_WAIT_1 ACK for FIN with ackno %u\n",
                           peer->receiver.local_addr, ack_segment.ackno);
                    tcp_process_fin_ack(peer, ack_segment.ackno);
                } else {
                    printk("  [RECV %x] FIN_WAIT_1 ACK from %u with window size %u\n",
                           peer->receiver.local_addr, ack_segment.ackno, ack_segment.window_size);
                    /* Regular ACK, not for our FIN */
                    sender_process_reply(&peer->sender, &ack_segment);
                }
            }
            break;

        case TCP_FIN_WAIT_2:
            /* Our FIN has been ACKed, waiting for remote FIN */
            if (is_fin) {
                /* Process FIN segment */
                sender_segment_t fin_segment = rcp_to_sender_segment(&datagram);
                tcp_process_fin(peer, &fin_segment);
            }
            break;

        case TCP_CLOSE_WAIT:
            /* Remote has sent FIN, we've ACKed it, app needs to close */
            if (is_ack) {
                /* Process ACK */
                receiver_segment_t ack_segment = rcp_to_receiver_segment(&datagram);
                sender_process_reply(&peer->sender, &ack_segment);
            }
            break;

        case TCP_CLOSING:
            /* Both sides initiated close */
            if (is_ack) {
                /* Process ACK - could be ACK for our FIN */
                receiver_segment_t ack_segment = rcp_to_receiver_segment(&datagram);

                /* Check if this ACK is for our FIN */
                if (ack_segment.ackno == peer->sender.next_seqno) {
                    tcp_process_fin_ack(peer, ack_segment.ackno);
                } else {
                    /* Regular ACK */
                    sender_process_reply(&peer->sender, &ack_segment);
                }
            }
            break;

        case TCP_LAST_ACK:
            /* We sent FIN after receiving remote FIN, waiting for ACK */
            if (is_ack) {
                /* Process ACK - could be ACK for our FIN */
                receiver_segment_t ack_segment = rcp_to_receiver_segment(&datagram);

                /* Check if this ACK is for our FIN */
                if (ack_segment.ackno == peer->sender.next_seqno) {
                    tcp_process_fin_ack(peer, ack_segment.ackno);
                } else {
                    /* Regular ACK */
                    sender_process_reply(&peer->sender, &ack_segment);
                }
            }
            break;

        case TCP_TIME_WAIT:
            /* We're waiting for delayed segments to expire */
            /* Just ACK any duplicate FINs that might arrive */
            if (is_fin) {
                sender_segment_t fin_segment = rcp_to_sender_segment(&datagram);

                /* Send an ACK for the FIN */
                receiver_segment_t ack = {.ackno = fin_segment.seqno + fin_segment.len + 1,
                                          .is_ack = true,
                                          .window_size = peer->receiver.window_size};

                sender_send_ack(&peer->sender, &ack);
            }
            break;

        case TCP_CLOSED:
            /* Connection is closed, ignore packets */
            break;
    }
}

/**
 * Actively open a connection (client side) by sending a SYN
 *
 * @param peer The TCP peer to connect
 * @return True if successful, false otherwise
 */
static inline bool tcp_connect(tcp_peer_t *peer) {
    assert(peer);

    if (peer->state == TCP_CLOSED) {
        return tcp_send_syn(peer);
    }

    return false;
}

/**
 * Send any data that's pending in the sender's buffer to the remote
 *
 * @param peer The TCP peer to process
 */
static inline void tcp_send_pending(tcp_peer_t *peer) {
    assert(peer);

    /* Check if a FIN needs to be sent */
    bool should_send_fin = false;

    /* Send FIN if we're in FIN_WAIT_1 or LAST_ACK and we need to initiate closure */
    if ((peer->state == TCP_FIN_WAIT_1 || peer->state == TCP_LAST_ACK) &&
        bs_reader_finished(&peer->sender.reader)) {
        /* Check if we've already sent a FIN */
        bool fin_already_sent = false;
        unacked_segment_t *seg = rtq_start(&peer->sender.pending_segs);

        while (seg != NULL) {
            if (seg->seg.is_fin) {
                fin_already_sent = true;
                break;
            }
            seg = seg->next;
        }

        /* If no FIN has been sent yet, send one */
        if (!fin_already_sent) {
            should_send_fin = true;
        }
    }

    /* Only send regular data if connection is established */
    if (peer->state == TCP_ESTABLISHED) {
        /* Try to push any pending data from the bytestream to the network */
        if (bs_bytes_available(&peer->sender.reader)) {
            sender_push(&peer->sender);
        }
    }

    /* Send FIN if needed */
    if (should_send_fin) {
        tcp_send_fin(peer);
    }
}

/**
 * Check for timeouts and handle retransmissions
 *
 * @param peer The TCP peer to process
 */
static inline void tcp_check_timeouts(tcp_peer_t *peer) {
    assert(peer);

    /* Check if any segments need to be retransmitted */
    sender_check_retransmits(&peer->sender);

    /* Handle connection establishment timeout */
    if ((peer->state == TCP_SYN_SENT || peer->state == TCP_SYN_RECEIVED) &&
        timer_get_usec() > peer->time_of_last_receipt + 3 * peer->sender.initial_RTO_us) {
        /* Retry handshake if too much time has passed */
        if (peer->state == TCP_SYN_SENT) {
            tcp_send_syn(peer);
        }
        /* For SYN_RECEIVED, retransmission is handled by sender_check_retransmits */
    }
}

/**
 * Main polling function that should be called regularly in your main loop
 *
 * @param peer The TCP peer to process
 */
static inline void tcp_tick(tcp_peer_t *peer) {
    assert(peer);

    tcp_check_incoming(peer);
    tcp_send_pending(peer);
    tcp_check_timeouts(peer);
}

/**
 * Write data to the TCP connection for sending
 *
 * @param peer The TCP peer to write to
 * @param data The data to write
 * @param len The length of the data
 * @return The number of bytes written
 */
static inline size_t tcp_write(tcp_peer_t *peer, const uint8_t *data, size_t len) {
    assert(peer);
    assert(data || len == 0);

    /* Only allow writing if connection is established */
    if (peer->state != TCP_ESTABLISHED) {
        return 0;
    }

    /* Write to the bytestream that the sender reads from */
    return bs_write(&peer->sender.reader, data, len);
}

/**
 * Read data from the TCP connection
 *
 * @param peer The TCP peer to read from
 * @param data The buffer to read into
 * @param len The maximum number of bytes to read
 * @return The number of bytes read
 */
static inline size_t tcp_read(tcp_peer_t *peer, uint8_t *data, size_t len) {
    assert(peer);
    assert(data || len == 0);

    /* Only allow reading if connection is established or closing */
    if (peer->state != TCP_ESTABLISHED && peer->state != TCP_CLOSE_WAIT &&
        peer->state != TCP_FIN_WAIT_1 && peer->state != TCP_FIN_WAIT_2) {
        return 0;
    }

    /* Read from the bytestream that the receiver writes to */
    return bs_read(&peer->receiver.writer, data, len);
}

/**
 * Check if the TCP connection has data available to read
 *
 * @param peer The TCP peer to check
 * @return True if there is data available, false otherwise
 */
static inline bool tcp_has_data(tcp_peer_t *peer) {
    assert(peer);

    /* Check if the receiver's bytestream has data available to read */
    return bs_bytes_available(&peer->receiver.writer) > 0;
}

/**
 * App can call this to close the TCP connection
 *
 * @param peer The TCP peer to close
 */
static inline void tcp_close(tcp_peer_t *peer) {
    assert(peer);

    /* Only proceed with closing if in an appropriate state */
    if (peer->state == TCP_ESTABLISHED || peer->state == TCP_CLOSE_WAIT) {
        /* Mark the sender's bytestream as finished */
        bs_end_input(&peer->sender.reader);

        /* Update state */
        if (peer->state == TCP_ESTABLISHED) {
            peer->state = TCP_FIN_WAIT_1;

            /* Immediately send a FIN if no data is pending */
            if (!bs_bytes_available(&peer->sender.reader)) {
                tcp_send_fin(peer);
            }
            /* Otherwise, FIN will be sent after data in tcp_send_pending */
        } else if (peer->state == TCP_CLOSE_WAIT) {
            peer->state = TCP_LAST_ACK;

            /* Always send FIN immediately in LAST_ACK state */
            tcp_send_fin(peer);
        }
    } else if (peer->state == TCP_SYN_SENT || peer->state == TCP_SYN_RECEIVED) {
        /* Abort connection attempt */
        peer->state = TCP_CLOSED;
    }
}

/**
 * Check if the TCP connection is active
 *
 * @param peer The TCP peer to check
 * @return True if the connection is still active
 */
static inline bool tcp_is_active(tcp_peer_t *peer) {
    assert(peer);

    uint32_t now = timer_get_usec();

    /* Connection is active if not in CLOSED or TIME_WAIT state that has expired */
    if (peer->state == TCP_CLOSED) {
        return false;
    }

    /* Check if the TIME_WAIT state has expired */
    uint32_t expire_time = peer->time_of_last_receipt + 2 * peer->sender.initial_RTO_us;
    printk("  [TCP] TIME_WAIT: current time %u, last receipt %u, RTO %u, expire_time %u\n", now,
           peer->time_of_last_receipt, peer->sender.initial_RTO_us, expire_time);
    if (peer->state == TCP_TIME_WAIT && now >= expire_time) {
        return false;
    }

    /* Sender is active if it has pending segments or is still reading from the app */
    bool sender_active =
        !rtq_empty(&peer->sender.pending_segs) || !bs_reader_finished(&peer->sender.reader);

    /* Receiver is active if it is still writing to the app */
    bool receiver_active = !bs_writer_finished(&peer->receiver.writer);

    /* We should linger for 10 RTOs after the last packet was received */
    bool lingering = peer->linger_after_streams_finish &&
                     (now < peer->time_of_last_receipt + 10 * peer->sender.initial_RTO_us);

    return (sender_active || receiver_active || lingering);
}

/**
 * Check if the receiving side of the connection is closed
 *
 * @param peer The TCP peer to check
 * @return True if the receiving side is closed
 */
static inline bool tcp_receive_closed(tcp_peer_t *peer) {
    assert(peer);

    /* Check if the receiver's bytestream is finished */
    return bs_writer_finished(&peer->receiver.writer);
}

/**
 * Check if the connection is established
 *
 * @param peer The TCP peer to check
 * @return True if the connection is established
 */
static inline bool tcp_is_established(tcp_peer_t *peer) {
    assert(peer);

    return peer->state == TCP_ESTABLISHED;
}
