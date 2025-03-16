#pragma once

#include "bytestream.h"
#include "nrf.h"
#include "queue-ext-T.h"
#include "receiver.h"
#include "router.h"
#include "sender.h"
#include "types.h"

/********* TYPES *********/

#define S_TO_US(s) ((s) * 1000000)
#define RTO_INITIAL_US S_TO_US(1)
#define TIME_WAIT_DURATION_US S_TO_US(2) /* 2-second TIME_WAIT */

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

static inline const char *tcp_state_to_string(tcp_state_t state) {
    switch (state) {
        case TCP_CLOSED:
            return "CLOSED";
        case TCP_LISTEN:
            return "LISTEN";
        case TCP_SYN_SENT:
            return "SYN_SENT";
        case TCP_SYN_RECEIVED:
            return "SYN_RECEIVED";
        case TCP_ESTABLISHED:
            return "ESTABLISHED";
        case TCP_FIN_WAIT_1:
            return "FIN_WAIT_1";
        case TCP_FIN_WAIT_2:
            return "FIN_WAIT_2";
        case TCP_CLOSE_WAIT:
            return "CLOSE_WAIT";
        case TCP_CLOSING:
            return "CLOSING";
        case TCP_LAST_ACK:
            return "LAST_ACK";
        case TCP_TIME_WAIT:
            return "TIME_WAIT";
        default:
            return "UNKNOWN";
    }
}

/* Callback function type for sending TCP segments */
typedef void (*tcp_send_callback_t)(void *ctx, uint8_t src, uint8_t dst, const void *data,
                                    size_t len);

/* Unacknowledged TCP segment for retransmission */
typedef struct unacked_tcp_segment {
    struct unacked_tcp_segment *next; /* Next in queue */
    tcp_segment_t segment;            /* Complete TCP segment (sender+receiver parts) */
    uint32_t time_sent;               /* Time when this segment was sent */
    uint32_t retransmit_count;        /* Number of times this segment has been retransmitted */
} unacked_tcp_segment_t;

/* Queue of unacknowledged segments */
typedef struct tcp_rtx_queue {
    unacked_tcp_segment_t *head, *tail;
} tcp_rtx_queue_t;

/* Generate queue functions for the TCP retransmission queue */
gen_queue_T(tcp_rtx, tcp_rtx_queue_t, head, tail, unacked_tcp_segment_t, next);

/* TCP peer structure representing a connection endpoint */
typedef struct tcp_peer {
    sender_t sender;     /* Sender component */
    receiver_t receiver; /* Receiver component */

    nrf_t *nrf;                        /* NRF interface for sending/receiving */
    tcp_send_callback_t send_callback; /* Callback for sending segments */
    void *callback_ctx;                /* Context for the callback */

    tcp_state_t state;                /* Current TCP connection state */
    tcp_rtx_queue_t rtx_queue;        /* Queue of segments that need acknowledgment */
    uint32_t initial_RTO_us;          /* Initial retransmission timeout */
    uint32_t time_of_last_receipt;    /* Time when last packet was received */
    uint32_t timeout_time_us;         /* Timeout for current state (e.g., TIME_WAIT timer) */
    bool linger_after_streams_finish; /* Whether to linger after streams finish */
} tcp_peer_t;

/********* HELPER FUNCTIONS *********/

/**
 * Convert an RCP datagram to a TCP segment
 *
 * @param datagram Pointer to the RCP datagram to convert
 * @return A TCP segment structure containing the converted data
 */
static inline tcp_segment_t rcp_to_tcp_segment(rcp_datagram_t *datagram) {
    assert(datagram);

    tcp_segment_t segment = {0};

    // Check for sender-side information (SYN, FIN, or data)
    bool has_sender_data = datagram->header.payload_len > 0 ||
                           rcp_has_flag(&datagram->header, RCP_FLAG_SYN) ||
                           rcp_has_flag(&datagram->header, RCP_FLAG_FIN);

    // Check for receiver-side information (ACK)
    bool has_receiver_data = rcp_has_flag(&datagram->header, RCP_FLAG_ACK);

    // Extract sender segment if present
    if (has_sender_data) {
        segment.has_sender_segment = true;
        segment.sender_segment.seqno = datagram->header.seqno;
        segment.sender_segment.is_syn = rcp_has_flag(&datagram->header, RCP_FLAG_SYN);
        segment.sender_segment.is_fin = rcp_has_flag(&datagram->header, RCP_FLAG_FIN);
        segment.sender_segment.len = datagram->header.payload_len;

        if (datagram->header.payload_len > 0) {
            memcpy(segment.sender_segment.payload, datagram->payload, datagram->header.payload_len);
        }
    }

    // Extract receiver segment if present
    if (has_receiver_data) {
        segment.has_receiver_segment = true;
        segment.receiver_segment.ackno = datagram->header.ackno;
        segment.receiver_segment.is_ack = true;
        segment.receiver_segment.window_size = datagram->header.window;
    }

    return segment;
}

/**
 * Convert a TCP segment to an RCP datagram
 *
 * @param segment Pointer to the TCP segment to convert
 * @param src Source RCP address
 * @param dst Destination RCP address
 * @return An RCP datagram containing the converted data
 */
static inline rcp_datagram_t tcp_segment_to_rcp(tcp_segment_t *segment, uint8_t src, uint8_t dst) {
    assert(segment);

    rcp_datagram_t datagram = rcp_datagram_init();

    // Set addressing
    datagram.header.src = src;
    datagram.header.dst = dst;

    // Set sender information if present
    if (segment->has_sender_segment) {
        datagram.header.seqno = segment->sender_segment.seqno;

        if (segment->sender_segment.is_syn) {
            rcp_set_flag(&datagram.header, RCP_FLAG_SYN);
        }

        if (segment->sender_segment.is_fin) {
            rcp_set_flag(&datagram.header, RCP_FLAG_FIN);
        }

        if (segment->sender_segment.len > 0) {
            rcp_datagram_set_payload(&datagram, segment->sender_segment.payload,
                                     segment->sender_segment.len);
        }
    }

    // Set receiver information if present
    if (segment->has_receiver_segment) {
        rcp_set_flag(&datagram.header, RCP_FLAG_ACK);
        datagram.header.ackno = segment->receiver_segment.ackno;
        datagram.header.window = segment->receiver_segment.window_size;
    }

    // Compute checksum
    rcp_datagram_compute_checksum(&datagram);

    return datagram;
}

/********* DEFAULT SEND CALLBACK *********/

/**
 * Default implementation of the send callback using NRF
 *
 * @param ctx Callback context (expected to be a tcp_peer_t pointer)
 * @param src Source RCP address
 * @param dst Destination RCP address
 * @param data Data to send
 * @param len Length of data to send
 */
static inline void tcp_default_send_callback(void *ctx, uint8_t src, uint8_t dst, const void *data,
                                             size_t len) {
    tcp_peer_t *peer = (tcp_peer_t *)ctx;
    assert(peer);
    printk("  [CALLBACK] peer_local: %u, peer_remote: %u, peer_local_nrf: %x, src: %u, dst: %u\n",
           peer->sender.local_addr, peer->sender.remote_addr, peer->nrf->rxaddr, src, dst);
    assert(peer->sender.local_addr == src);
    assert(peer->sender.remote_addr == dst);

    // Get the next hop NRF address from the routing table
    uint32_t next_hop_nrf = rtable_map[src][dst];

    printk(" [NRF] Sending data from %u (nrf: %x) to %u (nrf: %x)\n", src, peer->nrf->rxaddr, dst,
           next_hop_nrf);

    // Send the data via NRF
    nrf_send_noack(peer->nrf, next_hop_nrf, data, len);
}

/********* TCP PEER IMPLEMENTATION *********/

/**
 * Initialize a TCP peer with default state
 *
 * @param nrf The NRF interface for sending/receiving
 * @param local_addr Local RCP address
 * @param remote_addr Remote RCP address
 * @param is_server Whether this peer should act as a server (passive open)
 * @return Initialized TCP peer structure
 */
static inline tcp_peer_t tcp_peer_init(nrf_t *nrf, uint8_t local_addr, uint8_t remote_addr,
                                       bool is_server) {
    tcp_peer_t peer = {.sender = sender_init(local_addr, remote_addr),
                       .receiver = receiver_init(local_addr, remote_addr),
                       .nrf = nrf,
                       .send_callback = tcp_default_send_callback,
                       .callback_ctx = NULL,  // Will be set to &peer after initialization
                       .state = is_server ? TCP_LISTEN : TCP_CLOSED,
                       .initial_RTO_us = RTO_INITIAL_US,
                       .time_of_last_receipt = timer_get_usec(),
                       .timeout_time_us = 0,
                       .linger_after_streams_finish = true};

    // Initialize retransmission queue
    tcp_rtx_init(&peer.rtx_queue);

    // Set self as callback context
    peer.callback_ctx = &peer;

    // Verify the callback context
    tcp_peer_t *verify_peer = (tcp_peer_t *)peer.callback_ctx;
    assert(verify_peer == &peer);
    assert(verify_peer->sender.local_addr == peer.sender.local_addr);
    assert(verify_peer->sender.remote_addr == peer.sender.remote_addr);
    assert(verify_peer->receiver.local_addr == peer.receiver.local_addr);
    assert(verify_peer->receiver.remote_addr == peer.receiver.remote_addr);
    assert(verify_peer->state == peer.state);

    return peer;
}

/**
 * Set a custom send callback
 *
 * @param peer The TCP peer to update
 * @param callback The callback function to use
 * @param ctx Context to pass to the callback
 */
static inline void tcp_set_send_callback(tcp_peer_t *peer, tcp_send_callback_t callback,
                                         void *ctx) {
    assert(peer);

    peer->send_callback = callback;
    peer->callback_ctx = ctx;
}

/**
 * Send a TCP segment using the configured callback
 *
 * @param peer The TCP peer sending the segment
 * @param segment The segment to send
 * @param needs_ack Whether this segment needs acknowledgment (should be added to rtx queue)
 */
static inline void tcp_send_segment(tcp_peer_t *peer, tcp_segment_t *segment, bool needs_ack) {
    assert(peer);
    assert(segment);

    // Convert TCP segment to RCP datagram
    rcp_datagram_t datagram =
        tcp_segment_to_rcp(segment, peer->sender.local_addr, peer->sender.remote_addr);

    // Serialize the datagram
    uint8_t buffer[RCP_TOTAL_SIZE];
    int length = rcp_datagram_serialize(&datagram, buffer, RCP_TOTAL_SIZE);

    if (length <= 0) {
        printk("  [TCP] Failed to serialize datagram\n");
        return;
    }

    // Log sending information
    printk("  [TCP] Sending segment: ");
    if (segment->has_sender_segment) {
        printk("seqno=%u ", segment->sender_segment.seqno);
        if (segment->sender_segment.is_syn)
            printk("SYN ");
        if (segment->sender_segment.is_fin)
            printk("FIN ");
        printk("len=%u ", segment->sender_segment.len);
    }
    if (segment->has_receiver_segment) {
        printk("ackno=%u ", segment->receiver_segment.ackno);
        if (segment->receiver_segment.is_ack)
            printk("ACK ");
        printk("window=%u ", segment->receiver_segment.window_size);
    }
    printk("\n");

    // Send the segment using callback
    printk("  [CALLBACK] sending segment\n");
    peer->send_callback(peer->callback_ctx, peer->sender.local_addr, peer->sender.remote_addr,
                        buffer, length);

    // Add to retransmission queue if needed
    if (needs_ack && segment->has_sender_segment &&
        (segment->sender_segment.len > 0 || segment->sender_segment.is_syn ||
         segment->sender_segment.is_fin)) {
        // Create a new entry for the retransmission queue
        unacked_tcp_segment_t *rtx_segment = kmalloc(sizeof(unacked_tcp_segment_t));
        if (rtx_segment) {
            // Copy the segment and record time sent
            memcpy(&rtx_segment->segment, segment, sizeof(tcp_segment_t));
            rtx_segment->time_sent = timer_get_usec();
            rtx_segment->retransmit_count = 0;
            rtx_segment->next = NULL;

            // Add to queue
            tcp_rtx_push(&peer->rtx_queue, rtx_segment);

            // Update sender's sequence number
            sender_segment_sent(&peer->sender, &segment->sender_segment);
        }
    } else if (segment->has_sender_segment) {
        // Update sender's sequence number even if we don't need acknowledgment
        sender_segment_sent(&peer->sender, &segment->sender_segment);
    }
}

/**
 * Process an incoming TCP segment
 *
 * @param peer The TCP peer processing the segment
 * @param segment The segment to process
 */
static inline void tcp_process_segment(tcp_peer_t *peer, tcp_segment_t *segment) {
    assert(peer);
    assert(segment);

    printk(" [TCP] RCP %u: Processing received segment in state %s\n", peer->sender.local_addr,
           tcp_state_to_string(peer->state));
    printk("      - has_sender_segment: %u\n", segment->has_sender_segment);
    printk("      - has_receiver_segment: %u\n", segment->has_receiver_segment);
    if (segment->has_sender_segment) {
        printk("      - sender_segment.seqno: %u\n", segment->sender_segment.seqno);
        printk("      - sender_segment.is_syn: %u\n", segment->sender_segment.is_syn);
        printk("      - sender_segment.is_fin: %u\n", segment->sender_segment.is_fin);
        printk("      - sender_segment.len: %u\n", segment->sender_segment.len);
    }
    if (segment->has_receiver_segment) {
        printk("      - receiver_segment.ackno: %u\n", segment->receiver_segment.ackno);
        printk("      - receiver_segment.is_ack: %u\n", segment->receiver_segment.is_ack);
        printk("      - receiver_segment.window_size: %u\n", segment->receiver_segment.window_size);
    }
    printk("\n\n");

    // Update activity timestamp
    peer->time_of_last_receipt = timer_get_usec();

    // Process receiver part with sender
    if (segment->has_receiver_segment && segment->receiver_segment.is_ack) {
        printk(" [TCP] Processing ACK\n");
        // Update sender's acknowledged sequence number
        sender_process_ack(&peer->sender, &segment->receiver_segment);

        // Remove acknowledged segments from retransmission queue
        while (!tcp_rtx_empty(&peer->rtx_queue)) {
            unacked_tcp_segment_t *rtx_seg = tcp_rtx_start(&peer->rtx_queue);

            // Only consider segments with sender data
            if (!rtx_seg->segment.has_sender_segment) {
                tcp_rtx_pop(&peer->rtx_queue);
                continue;
            }

            // Calculate end sequence number for this segment
            uint16_t seg_end_seqno =
                rtx_seg->segment.sender_segment.seqno + rtx_seg->segment.sender_segment.len;

            if (rtx_seg->segment.sender_segment.is_syn || rtx_seg->segment.sender_segment.is_fin) {
                seg_end_seqno++;
            }

            // If this segment is fully acknowledged, remove it
            if (segment->receiver_segment.ackno >= seg_end_seqno) {
                printk(
                    " [TCP] Segment seqno %u fully acknowledged, removing from retransmission "
                    "queue\n",
                    rtx_seg->segment.sender_segment.seqno);
                tcp_rtx_pop(&peer->rtx_queue);
            } else {
                // Stop at first unacknowledged segment
                break;
            }
        }

        // Process ACKs for connection management
        switch (peer->state) {
            case TCP_SYN_SENT:
                if (segment->has_sender_segment && segment->sender_segment.is_syn) {
                    // Received SYN-ACK in response to our SYN
                    peer->state = TCP_ESTABLISHED;
                    printk("  [TCP] Connection established (client side)\n");
                }
                break;

            case TCP_SYN_RECEIVED:
                // Received ACK for our SYN-ACK
                peer->state = TCP_ESTABLISHED;
                printk("  [TCP] Connection established (server side)\n");
                break;

            case TCP_FIN_WAIT_1:
                // Received ACK for our FIN
                peer->state = TCP_FIN_WAIT_2;
                printk("  [TCP] FIN acknowledged, waiting for remote FIN\n");
                break;

            case TCP_CLOSING:
                // Received ACK for our FIN after receiving remote FIN
                peer->state = TCP_TIME_WAIT;
                peer->timeout_time_us = timer_get_usec() + TIME_WAIT_DURATION_US;
                printk("  [TCP] Entering TIME_WAIT state\n");
                break;

            case TCP_LAST_ACK:
                // Received ACK for our FIN (after we received remote FIN and closed)
                peer->state = TCP_CLOSED;
                printk("  [TCP] Connection closed\n");
                break;

            default:
                // Normal data ACK
                break;
        }
    }

    // Process sender part with receiver
    if (segment->has_sender_segment) {
        receiver_segment_t *recv_response = NULL;

        // SYN processing for connection establishment
        if (segment->sender_segment.is_syn) {
            switch (peer->state) {
                case TCP_LISTEN:
                    // Server received SYN from client
                    printk("  [TCP] Received SYN, sending SYN-ACK\n");

                    // Process with receiver
                    recv_response =
                        receiver_process_segment(&peer->receiver, &segment->sender_segment);

                    if (recv_response) {
                        // Create SYN-ACK response
                        tcp_segment_t syn_ack = {0};
                        syn_ack.has_receiver_segment = true;
                        syn_ack.receiver_segment = *recv_response;

                        // Add SYN to the response
                        syn_ack.has_sender_segment = true;
                        syn_ack.sender_segment.seqno = 0;  // Initial sequence number
                        syn_ack.sender_segment.is_syn = true;
                        syn_ack.sender_segment.is_fin = false;
                        syn_ack.sender_segment.len = 0;

                        // Send SYN-ACK
                        tcp_send_segment(peer, &syn_ack, true);

                        // Update state
                        peer->state = TCP_SYN_RECEIVED;
                    }
                    break;

                case TCP_SYN_SENT:
                    // Client received SYN from server (simultaneous open)
                    printk("  [TCP] Simultaneous open, received SYN while in SYN_SENT\n");

                    // Process with receiver
                    recv_response =
                        receiver_process_segment(&peer->receiver, &segment->sender_segment);

                    if (recv_response) {
                        // Send ACK for the SYN
                        tcp_segment_t ack_response = {0};
                        ack_response.has_receiver_segment = true;
                        ack_response.receiver_segment = *recv_response;

                        // Send ACK
                        tcp_send_segment(peer, &ack_response, false);
                    }
                    break;

                default:
                    // Duplicate SYN or invalid state
                    recv_response =
                        receiver_process_segment(&peer->receiver, &segment->sender_segment);

                    if (recv_response) {
                        // Just send ACK
                        tcp_segment_t ack_response = {0};
                        ack_response.has_receiver_segment = true;
                        ack_response.receiver_segment = *recv_response;

                        // Send ACK
                        tcp_send_segment(peer, &ack_response, false);
                    }
                    break;
            }
        }
        // FIN processing for connection termination
        else if (segment->sender_segment.is_fin) {
            printk("  [TCP] Received FIN\n");

            // Process with receiver
            recv_response = receiver_process_segment(&peer->receiver, &segment->sender_segment);

            if (recv_response) {
                // Send ACK for the FIN
                tcp_segment_t ack_response = {0};
                ack_response.has_receiver_segment = true;
                ack_response.receiver_segment = *recv_response;

                // Send ACK
                tcp_send_segment(peer, &ack_response, false);

                // Update state based on current state
                switch (peer->state) {
                    case TCP_ESTABLISHED:
                        // Remote initiated close
                        peer->state = TCP_CLOSE_WAIT;
                        printk("  [TCP] Remote closed, in CLOSE_WAIT state\n");
                        break;

                    case TCP_FIN_WAIT_1:
                        // We sent FIN, received FIN before our FIN was ACKed
                        peer->state = TCP_CLOSING;
                        printk("  [TCP] Simultaneous close, in CLOSING state\n");
                        break;

                    case TCP_FIN_WAIT_2:
                        // We sent FIN and it was ACKed, now remote sent FIN
                        peer->state = TCP_TIME_WAIT;
                        peer->timeout_time_us = timer_get_usec() + TIME_WAIT_DURATION_US;
                        printk("  [TCP] Received FIN after our FIN was ACKed, in TIME_WAIT\n");
                        break;

                    default:
                        // Invalid state for FIN
                        printk("  [TCP] Received FIN in invalid state %d\n", peer->state);
                        break;
                }
            }
        }
        // Regular data segment processing
        else {
            // Process with receiver
            recv_response = receiver_process_segment(&peer->receiver, &segment->sender_segment);

            if (recv_response) {
                // Check if we can piggyback data on the ACK
                sender_segment_t *new_data = sender_generate_segment(&peer->sender);

                if (new_data) {
                    // Send ACK with piggyback data
                    tcp_segment_t data_ack = {0};
                    data_ack.has_receiver_segment = true;
                    data_ack.receiver_segment = *recv_response;
                    data_ack.has_sender_segment = true;
                    data_ack.sender_segment = *new_data;

                    // Send combined segment
                    tcp_send_segment(peer, &data_ack, true);
                } else {
                    // Send pure ACK
                    tcp_segment_t ack_response = {0};
                    ack_response.has_receiver_segment = true;
                    ack_response.receiver_segment = *recv_response;

                    // Send ACK
                    tcp_send_segment(peer, &ack_response, false);
                }
            }
        }
    }
}

/**
 * Check for segments that need retransmission
 *
 * @param peer The TCP peer to check
 * @param current_time_us Current time in microseconds
 */
static inline void tcp_check_retransmits(tcp_peer_t *peer, uint32_t current_time_us) {
    assert(peer);

    if (tcp_rtx_empty(&peer->rtx_queue)) {
        return;
    }

    // Check the oldest unacknowledged segment
    unacked_tcp_segment_t *rtx_seg = tcp_rtx_start(&peer->rtx_queue);
    uint32_t rto = peer->initial_RTO_us * (1 << rtx_seg->retransmit_count);

    // If it's time to retransmit
    if (current_time_us >= rtx_seg->time_sent + rto) {
        printk("  [TCP] Retransmitting segment (retry %u)\n", rtx_seg->retransmit_count + 1);

        // Update retransmission count and time
        rtx_seg->retransmit_count++;
        rtx_seg->time_sent = current_time_us;

        // Send the segment again
        tcp_send_segment(peer, &rtx_seg->segment, false);  // Don't add to queue again
    }
}

/**
 * Try to generate and send new data
 *
 * @param peer The TCP peer to check
 */
static inline void tcp_send_new_data(tcp_peer_t *peer) {
    assert(peer);

    // Only send if in established state or closing
    if (peer->state != TCP_ESTABLISHED && peer->state != TCP_CLOSE_WAIT &&
        peer->state != TCP_FIN_WAIT_1) {
        return;
    }

    // Try to generate a new segment
    sender_segment_t *new_segment = sender_generate_segment(&peer->sender);

    if (new_segment) {
        // Create a TCP segment with the new data
        tcp_segment_t data_segment = {0};
        data_segment.has_sender_segment = true;
        data_segment.sender_segment = *new_segment;

        // If the app closed during FIN_WAIT_1, add an ACK to the FIN
        if (new_segment->is_fin && peer->state == TCP_CLOSE_WAIT) {
            peer->state = TCP_LAST_ACK;
            printk("  [TCP] Sending FIN, entering LAST_ACK state\n");
        } else if (new_segment->is_fin && peer->state == TCP_ESTABLISHED) {
            peer->state = TCP_FIN_WAIT_1;
            printk("  [TCP] Sending FIN, entering FIN_WAIT_1 state\n");
        }

        // Send the segment
        tcp_send_segment(peer, &data_segment, true);
    }
}

/**
 * Main polling function that should be called regularly in your main loop
 *
 * @param peer The TCP peer to process
 */
static inline void tcp_tick(tcp_peer_t *peer) {
    assert(peer);

    uint32_t current_time = timer_get_usec();

    // Check for incoming packets
    uint8_t buffer[RCP_TOTAL_SIZE];
    int ret = nrf_read_exact_timeout(peer->nrf, buffer, RCP_TOTAL_SIZE, 1000);

    printk(" [NRF] Received packet at nrf: %x\n", peer->nrf->rxaddr);

    if (ret > 0) {
        // Parse the datagram
        rcp_datagram_t datagram = rcp_datagram_init();
        if (!rcp_datagram_parse(&datagram, buffer, ret)) {
            printk(" [RCP] Failed to parse datagram\n");
            return;
        }

        if (!rcp_datagram_verify_checksum(&datagram)) {
            printk(" [RCP] Checksum verification failed\n");
            return;
        }

        // Convert to TCP segment
        tcp_segment_t segment = rcp_to_tcp_segment(&datagram);

        // Process the segment
        tcp_process_segment(peer, &segment);
    }

    // Check if TIME_WAIT timer has expired
    if (peer->state == TCP_TIME_WAIT && current_time >= peer->timeout_time_us) {
        peer->state = TCP_CLOSED;
        printk("  [TCP] TIME_WAIT expired, connection closed\n");
    }

    // Check for retransmissions
    tcp_check_retransmits(peer, current_time);

    // Try to send new data
    tcp_send_new_data(peer);
}

/********* CONNECTION MANAGEMENT *********/

/**
 * Actively open a connection (client side) by sending a SYN
 *
 * @param peer The TCP peer to connect
 * @return True if successful, false otherwise
 */
static inline bool tcp_connect(tcp_peer_t *peer) {
    assert(peer);

    if (peer->state != TCP_CLOSED) {
        return false;
    }

    // Create SYN segment
    tcp_segment_t syn_segment = {0};
    syn_segment.has_sender_segment = true;
    syn_segment.sender_segment.seqno = 0;  // Initial sequence number
    syn_segment.sender_segment.is_syn = true;
    syn_segment.sender_segment.is_fin = false;
    syn_segment.sender_segment.len = 0;

    // Send SYN
    tcp_send_segment(peer, &syn_segment, true);

    // Update state
    peer->state = TCP_SYN_SENT;
    printk("  [TCP] Sent SYN, entering SYN_SENT state\n");

    return true;
}

/**
 * App can call this to close the TCP connection
 *
 * @param peer The TCP peer to close
 */
static inline void tcp_close(tcp_peer_t *peer) {
    assert(peer);

    switch (peer->state) {
        case TCP_ESTABLISHED:
            // Mark the sender's bytestream as finished
            bs_end_input(&peer->sender.reader);

            // Try to generate and send a FIN segment immediately
            tcp_send_new_data(peer);
            break;

        case TCP_CLOSE_WAIT:
            // Remote side already closed, we need to close our side
            bs_end_input(&peer->sender.reader);

            // Try to generate and send a FIN segment immediately
            tcp_send_new_data(peer);
            break;

        case TCP_SYN_SENT:
        case TCP_SYN_RECEIVED:
            // Abort connection attempt
            peer->state = TCP_CLOSED;
            printk("  [TCP] Connection attempt aborted\n");
            break;

        default:
            // No action needed in other states
            break;
    }
}

/********* DATA TRANSFER *********/

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

    // Only allow writing if connection is established
    if (peer->state != TCP_ESTABLISHED && peer->state != TCP_CLOSE_WAIT) {
        return 0;
    }

    // Write to the bytestream that the sender reads from
    size_t bytes_written = bs_write(&peer->sender.reader, data, len);

    // Try to send data immediately
    tcp_send_new_data(peer);

    return bytes_written;
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

    // Read from the bytestream that the receiver writes to
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

    // Check if the receiver's bytestream has data available to read
    return bs_bytes_available(&peer->receiver.writer) > 0;
}

/**
 * Check if the receiving side of the connection is closed
 *
 * @param peer The TCP peer to check
 * @return True if the receiving side is closed
 */
static inline bool tcp_receive_closed(tcp_peer_t *peer) {
    assert(peer);

    // Check if the receiver's bytestream is finished
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

/**
 * Check if the TCP connection is active
 *
 * @param peer The TCP peer to check
 * @return True if the connection is still active
 */
static inline bool tcp_is_active(tcp_peer_t *peer) {
    assert(peer);

    // Connection is closed
    if (peer->state == TCP_CLOSED) {
        return false;
    }

    // Check streams status
    bool sender_active =
        !bs_reader_finished(&peer->sender.reader) || !tcp_rtx_empty(&peer->rtx_queue);
    bool receiver_active = !bs_writer_finished(&peer->receiver.writer);

    // If in TIME_WAIT state, check timer
    if (peer->state == TCP_TIME_WAIT) {
        return timer_get_usec() < peer->timeout_time_us;
    }

    // Check if we should linger
    uint32_t now = timer_get_usec();
    bool lingering = peer->linger_after_streams_finish &&
                     (now < peer->time_of_last_receipt + 10 * peer->initial_RTO_us);

    return sender_active || receiver_active || lingering;
}

/**
 * Clean up a TCP connection and free resources
 *
 * @param peer The TCP peer to clean up
 */
static inline void tcp_cleanup(tcp_peer_t *peer) {
    assert(peer);

    // Clean up the retransmission queue
    while (!tcp_rtx_empty(&peer->rtx_queue)) {
        unacked_tcp_segment_t *seg = tcp_rtx_pop(&peer->rtx_queue);
    }
}