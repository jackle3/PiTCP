#pragma once

#include "bytestream.h"
#include "nrf.h"
#include "queue-ext-T.h"
#include "receiver.h"
#include "router.h"
#include "sender.h"
#include "types.h"

// #define VERBOSE
#ifdef VERBOSE
#define VERBOSE_PRINT(fmt, args...) printk(fmt, ##args)
#else
#define VERBOSE_PRINT(fmt, args...) /* nothing */
#endif

/********* TYPES *********/

#define S_TO_US(s) ((s) * 1000000)
#define RTO_INITIAL_US S_TO_US(1)
#define TIME_WAIT_DURATION_US S_TO_US(2) /* 2-second TIME_WAIT */

/* TCP statistics structure */
typedef struct tcp_stats {
    /* Segments */
    uint32_t segments_sent;      /* Total segments sent */
    uint32_t data_segments_sent; /* Data segments sent */
    uint32_t syn_segments_sent;  /* SYN segments sent */
    uint32_t fin_segments_sent;  /* FIN segments sent */
    uint32_t ack_segments_sent;  /* ACK segments sent */

    uint32_t segments_received;      /* Total segments received */
    uint32_t data_segments_received; /* Data segments received */
    uint32_t syn_segments_received;  /* SYN segments received */
    uint32_t fin_segments_received;  /* FIN segments received */
    uint32_t ack_segments_received;  /* ACK segments received */

    /* Retransmissions */
    uint32_t retransmits;           /* Total retransmitted segments */
    uint32_t dup_acks_received;     /* Duplicate ACKs received */
    uint32_t out_of_order_received; /* Out-of-order segments received */

    /* Throughput */
    uint32_t bytes_sent;          /* Total bytes sent */
    uint32_t bytes_received;      /* Total bytes received */
    uint32_t bytes_retransmitted; /* Total bytes retransmitted */

    /* Timers */
    uint32_t connection_start_time_us; /* When connection was established */
    uint32_t last_send_time_us;        /* Last time a segment was sent */
    uint32_t last_recv_time_us;        /* Last time a segment was received */
} tcp_stats_t;

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
typedef void (*tcp_send_callback_t)(nrf_t *nrf, uint8_t src, uint8_t dst, const void *data,
                                    size_t len);

/* Unacknowledged TCP segment for retransmission */
typedef struct unacked_tcp_segment {
    struct unacked_tcp_segment *next; /* Next in queue */
    tcp_segment_t segment;            /* Complete TCP segment (sender+receiver parts) */
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

    tcp_state_t state;        /* Current TCP connection state */
    uint32_t timeout_time_us; /* Timeout for current state (e.g., TIME_WAIT timer) */

    tcp_rtx_queue_t rtx_queue;  /* Queue of segments that need acknowledgment */
    uint32_t segs_in_flight;    /* Number of segments in flight */
    uint32_t initial_RTO_us;    /* Initial retransmission timeout */
    uint32_t rto_us;            /* Next time to retransmit - when time >= rto_us, retransmit */
    int16_t consec_retransmits; /* Number of consecutive retransmits */

    tcp_stats_t stats; /* Statistics for the TCP connection */
} tcp_peer_t;

/********* STATISTICS TRACKING *********/

/**
 * Initialize the TCP statistics structure
 *
 * @return Initialized TCP statistics structure with zeroed values
 */
static inline tcp_stats_t tcp_stats_init(void) {
    tcp_stats_t stats = {0};
    stats.connection_start_time_us = timer_get_usec();
    stats.last_send_time_us = stats.connection_start_time_us;
    stats.last_recv_time_us = stats.connection_start_time_us;
    return stats;
}

/**
 * Update TCP statistics when sending a segment
 *
 * @param peer The TCP peer
 * @param segment The segment being sent
 */
static inline void tcp_update_send_stats(tcp_peer_t *peer, tcp_segment_t *segment) {
    peer->stats.segments_sent++;
    peer->stats.last_send_time_us = timer_get_usec();

    if (segment->has_sender_segment) {
        if (segment->sender_segment.len > 0) {
            peer->stats.data_segments_sent++;
            peer->stats.bytes_sent += segment->sender_segment.len;
        }
        if (segment->sender_segment.is_syn) {
            peer->stats.syn_segments_sent++;
        }
        if (segment->sender_segment.is_fin) {
            peer->stats.fin_segments_sent++;
        }
    }

    if (segment->has_receiver_segment && segment->receiver_segment.is_ack) {
        peer->stats.ack_segments_sent++;
    }
}

/**
 * Update TCP statistics when receiving a segment
 *
 * @param peer The TCP peer
 * @param segment The segment received
 */
static inline void tcp_update_receive_stats(tcp_peer_t *peer, tcp_segment_t *segment) {
    peer->stats.segments_received++;
    peer->stats.last_recv_time_us = timer_get_usec();

    if (segment->has_sender_segment) {
        if (segment->sender_segment.len > 0) {
            peer->stats.data_segments_received++;
            peer->stats.bytes_received += segment->sender_segment.len;
        }
        if (segment->sender_segment.is_syn) {
            peer->stats.syn_segments_received++;
        }
        if (segment->sender_segment.is_fin) {
            peer->stats.fin_segments_received++;
        }
    }

    if (segment->has_receiver_segment && segment->receiver_segment.is_ack) {
        peer->stats.ack_segments_received++;
    }
}

/**
 * Update TCP statistics for retransmissions
 *
 * @param peer The TCP peer
 * @param segment The segment being retransmitted
 */
static inline void tcp_update_retransmit_stats(tcp_peer_t *peer, tcp_segment_t *segment) {
    peer->stats.retransmits++;

    if (segment->has_sender_segment && segment->sender_segment.len > 0) {
        peer->stats.bytes_retransmitted += segment->sender_segment.len;
    }
}

/**
 * Calculate current send throughput in bytes per second
 *
 * @param peer The TCP peer
 * @return Current throughput in bytes per second
 */
static inline size_t tcp_calculate_throughput(tcp_peer_t *peer) {
    uint32_t now_us = timer_get_usec();
    uint32_t elapsed_us = now_us - peer->stats.connection_start_time_us;

    if (elapsed_us == 0) {
        return 0;
    }

    return peer->stats.bytes_sent / (elapsed_us / 1000000);
}

/**
 * Print TCP connection statistics
 *
 * @param peer The TCP peer
 */
static inline void tcp_print_stats(tcp_peer_t *peer) {
    printk("===== TCP Connection Statistics =====\n");
    printk("Connection State: %s\n", tcp_state_to_string(peer->state));
    printk("Connection Duration: %u seconds\n",
           (timer_get_usec() - peer->stats.connection_start_time_us) / 1000000);

    printk("\n--- Segments ---\n");
    printk("Segments Sent: %u (Data: %u, SYN: %u, FIN: %u, ACK: %u)\n", peer->stats.segments_sent,
           peer->stats.data_segments_sent, peer->stats.syn_segments_sent,
           peer->stats.fin_segments_sent, peer->stats.ack_segments_sent);

    printk("Segments Received: %u (Data: %u, SYN: %u, FIN: %u, ACK: %u)\n",
           peer->stats.segments_received, peer->stats.data_segments_received,
           peer->stats.syn_segments_received, peer->stats.fin_segments_received,
           peer->stats.ack_segments_received);

    printk("\n--- Retransmissions ---\n");
    printk("Retransmitted Segments: %u\n", peer->stats.retransmits);
    printk("Current Segments in Flight: %u\n", peer->segs_in_flight);

    printk("\n--- Throughput ---\n");
    printk("Bytes Sent: %u\n", peer->stats.bytes_sent);
    printk("Bytes Received: %u\n", peer->stats.bytes_received);
    printk("Bytes Retransmitted: %u\n", peer->stats.bytes_retransmitted);
    printk("Send Throughput: %u bytes/sec\n", tcp_calculate_throughput(peer));

    printk("\n--- Window Information ---\n");
    printk("Send Window Size: %u\n", peer->sender.window_size);
    printk("Receive Window Size: %u\n", peer->receiver.window_size);

    printk("===================================\n");
}

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
    bool has_sender_data = rcp_get_payload_len(&datagram->header) > 0 ||
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
        segment.sender_segment.len = rcp_get_payload_len(&datagram->header);

        if (rcp_get_payload_len(&datagram->header) > 0) {
            memcpy(segment.sender_segment.payload, datagram->payload,
                   rcp_get_payload_len(&datagram->header));
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
    rcp_set_src_addr(&datagram.header, src);
    rcp_set_dst_addr(&datagram.header, dst);

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
 * @param nrf The NRF interface for sending/receiving
 * @param src Source RCP address
 * @param dst Destination RCP address
 * @param data Data to send
 * @param len Length of data to send
 */
static inline void tcp_default_send_callback(nrf_t *nrf, uint8_t src, uint8_t dst, const void *data,
                                             size_t len) {
    assert(nrf);
    // Get the next hop NRF address from the routing table
    uint32_t next_hop_nrf = rtable_map[src][dst];

    DEBUG_PRINT(" [NRF] Sending data from %u (nrf: %x) to %u (nrf: %x)\n", src, nrf->rxaddr, dst,
                next_hop_nrf);

    // Send the data via NRF
    nrf_send_noack(nrf, next_hop_nrf, data, len);
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
                       .state = is_server ? TCP_LISTEN : TCP_CLOSED,
                       .initial_RTO_us = RTO_INITIAL_US,
                       .rto_us = 0,
                       .consec_retransmits = -1, /* Initialize to -1 to indicate not started */
                       .timeout_time_us = 0,
                       .stats = tcp_stats_init()}; /* Initialize stats */

    // Initialize retransmission queue
    tcp_rtx_init(&peer.rtx_queue);

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

    // Update send statistics
    tcp_update_send_stats(peer, segment);

    // Convert TCP segment to RCP datagram
    rcp_datagram_t datagram =
        tcp_segment_to_rcp(segment, peer->sender.local_addr, peer->sender.remote_addr);

    // Serialize the datagram
    uint8_t buffer[RCP_TOTAL_SIZE];
    int length = rcp_datagram_serialize(&datagram, buffer, RCP_TOTAL_SIZE);

    if (length <= 0) {
        VERBOSE_PRINT("  [TCP %x] Failed to serialize datagram\n", peer->sender.local_addr);
        return;
    }

    // Log sending information
    uint32_t next_hop_nrf = rtable_map[peer->sender.local_addr][peer->sender.remote_addr];
    VERBOSE_PRINT("  [TCP %x] Sending segment from NRF %x to NRF %x: ", peer->sender.local_addr,
                  peer->nrf->rxaddr, next_hop_nrf);
    if (segment->has_sender_segment) {
        VERBOSE_PRINT("seqno=%u ", segment->sender_segment.seqno);
        if (segment->sender_segment.is_syn)
            VERBOSE_PRINT("syn=1 ");
        if (segment->sender_segment.is_fin)
            VERBOSE_PRINT("fin=1 ");
        VERBOSE_PRINT("len=%u ", segment->sender_segment.len);
    }
    if (segment->has_receiver_segment) {
        VERBOSE_PRINT("ackno=%u ", segment->receiver_segment.ackno);
        if (segment->receiver_segment.is_ack)
            VERBOSE_PRINT("ack=1 ");
        VERBOSE_PRINT("window=%u ", segment->receiver_segment.window_size);
    }
    VERBOSE_PRINT("\n");

    // Send the segment using callback
    peer->send_callback(peer->nrf, peer->sender.local_addr, peer->sender.remote_addr, buffer,
                        length);

    // Add to retransmission queue if needed
    if (needs_ack && segment->has_sender_segment &&
        (segment->sender_segment.len > 0 || segment->sender_segment.is_syn ||
         segment->sender_segment.is_fin)) {
        // Create a new entry for the retransmission queue
        unacked_tcp_segment_t *rtx_segment = kmalloc(sizeof(unacked_tcp_segment_t));
        if (rtx_segment) {
            // Initialize the retransmission timer if not already started
            if (peer->consec_retransmits == -1) {
                peer->rto_us = timer_get_usec() + peer->initial_RTO_us;
                peer->consec_retransmits = 0;
            }

            // Add to the end of the queue
            memcpy(&rtx_segment->segment, segment, sizeof(tcp_segment_t));

            VERBOSE_PRINT("  [TCP %x] Adding segment to retransmission queue: ",
                          peer->sender.local_addr);
            if (rtx_segment->segment.has_sender_segment) {
                VERBOSE_PRINT("seqno=%u ", rtx_segment->segment.sender_segment.seqno);
                if (rtx_segment->segment.sender_segment.is_syn)
                    VERBOSE_PRINT("syn=1 ");
                if (rtx_segment->segment.sender_segment.is_fin)
                    VERBOSE_PRINT("fin=1 ");
                VERBOSE_PRINT("len=%u ", rtx_segment->segment.sender_segment.len);
            }
            if (rtx_segment->segment.has_receiver_segment) {
                VERBOSE_PRINT("ackno=%u ", rtx_segment->segment.receiver_segment.ackno);
                if (rtx_segment->segment.receiver_segment.is_ack)
                    VERBOSE_PRINT("ack=1 ");
                VERBOSE_PRINT("window=%u ", rtx_segment->segment.receiver_segment.window_size);
            }
            VERBOSE_PRINT("\n");

            tcp_rtx_append(&peer->rtx_queue, rtx_segment);
            peer->segs_in_flight++;

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

    // Update receive statistics
    tcp_update_receive_stats(peer, segment);

    DEBUG_PRINT(" [TCP] RCP %u: Processing received segment in state %s\n", peer->sender.local_addr,
                tcp_state_to_string(peer->state));
    DEBUG_PRINT("      - has_sender_segment: %u\n", segment->has_sender_segment);
    DEBUG_PRINT("      - has_receiver_segment: %u\n", segment->has_receiver_segment);
    if (segment->has_sender_segment) {
        DEBUG_PRINT("      - sender_segment.seqno: %u\n", segment->sender_segment.seqno);
        DEBUG_PRINT("      - sender_segment.is_syn: %u\n", segment->sender_segment.is_syn);
        DEBUG_PRINT("      - sender_segment.is_fin: %u\n", segment->sender_segment.is_fin);
        DEBUG_PRINT("      - sender_segment.len: %u\n", segment->sender_segment.len);
    }
    if (segment->has_receiver_segment) {
        DEBUG_PRINT("      - receiver_segment.ackno: %u\n", segment->receiver_segment.ackno);
        DEBUG_PRINT("      - receiver_segment.is_ack: %u\n", segment->receiver_segment.is_ack);
        DEBUG_PRINT("      - receiver_segment.window_size: %u\n",
                    segment->receiver_segment.window_size);
    }
    DEBUG_PRINT("\n\n");

    // Process receiver part with sender
    if (segment->has_receiver_segment && segment->receiver_segment.is_ack) {
        DEBUG_PRINT(" [TCP] Processing ACK\n");

        // Update sender's acknowledged sequence number
        sender_process_ack(&peer->sender, &segment->receiver_segment);

        // Remove acknowledged segments from retransmission queue
        bool new_data_acked = false;
        while (!tcp_rtx_empty(&peer->rtx_queue)) {
            unacked_tcp_segment_t *rtx_seg = tcp_rtx_start(&peer->rtx_queue);

            // Only consider segments with sender data
            if (!rtx_seg->segment.has_sender_segment) {
                tcp_rtx_pop(&peer->rtx_queue);
                peer->segs_in_flight--;
                continue;
            }

            // Calculate end sequence number for this segment
            uint32_t seg_abs_seqno =
                unwrap_seqno(rtx_seg->segment.sender_segment.seqno, peer->sender.next_seqno);
            uint32_t seg_end_seqno = seg_abs_seqno + rtx_seg->segment.sender_segment.len;

            if (rtx_seg->segment.sender_segment.is_syn || rtx_seg->segment.sender_segment.is_fin) {
                seg_end_seqno++;
            }

            // Queue is sorted by absolute seqno, so stop once we find an unacked segment
            if (peer->sender.acked_seqno < seg_end_seqno) {
                break;
            }

            DEBUG_PRINT(" [TCP] Segment seqno %u fully acknowledged, removing from rtx queue\n",
                        rtx_seg->segment.sender_segment.seqno);

            tcp_rtx_pop(&peer->rtx_queue);
            peer->segs_in_flight--;
            new_data_acked = true;
        }

        // If new data was acknowledged, reset the retransmission timer
        if (new_data_acked) {
            VERBOSE_PRINT("  [TCP %x] New data acknowledged, resetting RTO\n",
                          peer->sender.local_addr);
            peer->rto_us = timer_get_usec() + peer->initial_RTO_us;
            peer->consec_retransmits = 0;
        }

        // If all data has been acknowledged, stop the retransmission timer
        if (tcp_rtx_empty(&peer->rtx_queue)) {
            peer->rto_us = 0;
            peer->consec_retransmits = -1;
        }

        // Process ACKs for connection management
        switch (peer->state) {
            case TCP_SYN_SENT:
                if (segment->has_sender_segment && segment->sender_segment.is_syn) {
                    // Received SYN-ACK in response to our SYN
                    peer->state = TCP_ESTABLISHED;
                    VERBOSE_PRINT("  [TCP %x] Connection established (client side)\n",
                                  peer->sender.local_addr);
                }
                break;

            case TCP_SYN_RECEIVED:
                // Received ACK for our SYN-ACK
                peer->state = TCP_ESTABLISHED;
                VERBOSE_PRINT("  [TCP %x] Connection established (server side)\n",
                              peer->sender.local_addr);
                break;

            case TCP_FIN_WAIT_1:
                // Received ACK for our FIN
                peer->state = TCP_FIN_WAIT_2;
                VERBOSE_PRINT("  [TCP %x] FIN acknowledged, waiting for remote FIN\n",
                              peer->sender.local_addr);
                break;

            case TCP_CLOSING:
                // Received ACK for our FIN after receiving remote FIN
                peer->state = TCP_TIME_WAIT;
                peer->timeout_time_us = timer_get_usec() + TIME_WAIT_DURATION_US;
                VERBOSE_PRINT("  [TCP %x] Entering TIME_WAIT state\n", peer->sender.local_addr);
                break;

            case TCP_LAST_ACK:
                // Received ACK for our FIN (after we received remote FIN and closed)
                peer->state = TCP_CLOSED;
                VERBOSE_PRINT("  [TCP %x] Connection closed\n", peer->sender.local_addr);
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
                    VERBOSE_PRINT("  [TCP %x] Received SYN, sending SYN-ACK\n",
                                  peer->sender.local_addr);

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
                    VERBOSE_PRINT("  [TCP %x] Simultaneous open, received SYN while in SYN_SENT\n",
                                  peer->sender.local_addr);

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
            VERBOSE_PRINT("  [TCP %x] Received FIN\n", peer->sender.local_addr);

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
                        printk("  [TCP %x] Remote closed, in CLOSE_WAIT state\n",
                               peer->sender.local_addr);
                        break;

                    case TCP_FIN_WAIT_1:
                        // We sent FIN, received FIN before our FIN was ACKed
                        peer->state = TCP_CLOSING;
                        VERBOSE_PRINT("  [TCP %x] Simultaneous close, in CLOSING state\n",
                                      peer->sender.local_addr);
                        break;

                    case TCP_FIN_WAIT_2:
                        // We sent FIN and it was ACKed, now remote sent FIN
                        peer->state = TCP_TIME_WAIT;
                        peer->timeout_time_us = timer_get_usec() + TIME_WAIT_DURATION_US;
                        VERBOSE_PRINT(
                            "  [TCP %x] Received FIN after our FIN was ACKed, in TIME_WAIT\n",
                            peer->sender.local_addr);
                        break;

                    default:
                        // Invalid state for FIN
                        VERBOSE_PRINT("  [TCP %x] Received FIN in invalid state %d\n",
                                      peer->sender.local_addr, peer->state);
                        break;
                }
            }
        }
        // Regular data segment processing
        else {
            // If we've already received the remote FIN and get another packet, panic
            if (peer->state == TCP_CLOSE_WAIT) {
                // Remote side already sent FIN but is now sending more data
                printk("  [TCP %x] ERROR: Received data after FIN in CLOSE_WAIT state\n",
                       peer->sender.local_addr);

                // Print debug info about the unexpected packet
                printk("    Sender Segment: seqno=%u (abs %u), len=%u\n",
                       segment->sender_segment.seqno,
                       unwrap_seqno(segment->sender_segment.seqno, peer->sender.next_seqno),
                       segment->sender_segment.len);

                panic("TCP protocol violation: received data after FIN");
            }

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

    // We don't need to retransmit if we're not in the retransmission state
    if (peer->consec_retransmits == -1 || tcp_rtx_empty(&peer->rtx_queue)) {
        return;
    }

    // Print out the entire retransmission queue for debugging
    VERBOSE_PRINT("[TCP %x] Retransmission queue contents:\n", peer->sender.local_addr);
    unacked_tcp_segment_t *current = tcp_rtx_start(&peer->rtx_queue);
    int count = 0;
    while (current != NULL) {
        VERBOSE_PRINT("    [%d] seqno: %u, len: %u\n", count, current->segment.sender_segment.seqno,
                      current->segment.sender_segment.len);
        // Check if segment has SYN or FIN flags
        if (current->segment.sender_segment.is_syn) {
            VERBOSE_PRINT("        SYN flag set\n");
        }
        if (current->segment.sender_segment.is_fin) {
            VERBOSE_PRINT("        FIN flag set\n");
        }
        count++;
        current = current->next;
    }
    VERBOSE_PRINT("  [TCP %x] Total segments in queue: %d\n", peer->sender.local_addr, count);

    uint32_t now_us = timer_get_usec();
    int32_t time_since_rto = now_us - peer->rto_us;

    if (time_since_rto >= 0) {
        // Send the oldest unacknowledged segment
        unacked_tcp_segment_t *rtx_seg = tcp_rtx_start(&peer->rtx_queue);

        // Update retransmission statistics
        tcp_update_retransmit_stats(peer, &rtx_seg->segment);

        tcp_send_segment(peer, &rtx_seg->segment, false);  // Don't add to queue again

        printk("  [TCP %x] Retransmitting segment (retry %u): seqno=%u (abs %u), len=%u\n",
               peer->sender.local_addr, peer->consec_retransmits + 1,
               rtx_seg->segment.sender_segment.seqno,
               unwrap_seqno(rtx_seg->segment.sender_segment.seqno, peer->sender.next_seqno),
               rtx_seg->segment.sender_segment.len);

        // Update retransmission timer - use exponential backoff if window is nonzero
        if (peer->sender.window_size) {
            // Exponential backoff: double RTO for each retransmission
            peer->rto_us = now_us + (peer->initial_RTO_us * (1 << peer->consec_retransmits));
            peer->consec_retransmits++;
        } else {
            // If window is zero, use fixed RTO for persistent probing
            peer->rto_us = now_us + peer->initial_RTO_us;
        }
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

    DEBUG_PRINT(" [TCP] Sending new data\n");
    DEBUG_PRINT("      - new_segment->is_fin: %u\n", new_segment->is_fin);
    DEBUG_PRINT("      - peer->state: %s\n", tcp_state_to_string(peer->state));

    if (new_segment) {
        // Create a TCP segment with the new data
        tcp_segment_t data_segment = {0};
        data_segment.has_sender_segment = true;
        data_segment.sender_segment = *new_segment;

        // If the app closed during FIN_WAIT_1, add an ACK to the FIN
        if (new_segment->is_fin && peer->state == TCP_CLOSE_WAIT) {
            peer->state = TCP_LAST_ACK;
            VERBOSE_PRINT("  [TCP %x] Sending FIN, entering LAST_ACK state\n",
                          peer->sender.local_addr);
        } else if (new_segment->is_fin && peer->state == TCP_ESTABLISHED) {
            peer->state = TCP_FIN_WAIT_1;
            VERBOSE_PRINT("  [TCP %x] Sending FIN, entering FIN_WAIT_1 state\n",
                          peer->sender.local_addr);
        }

        VERBOSE_PRINT("  [TCP %x] Sending new data: seqno=%u, len=%u\n", peer->sender.local_addr,
                      new_segment->seqno, new_segment->len);

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

    DEBUG_PRINT(" [NRF] Received packet at nrf: %x\n", peer->nrf->rxaddr);

    if (ret > 0) {
        // Parse the datagram
        rcp_datagram_t datagram = rcp_datagram_init();
        if (!rcp_datagram_parse(&datagram, buffer, ret)) {
            VERBOSE_PRINT(" [RCP] Failed to parse datagram\n");
            return;
        }

        if (!rcp_datagram_verify_checksum(&datagram)) {
            VERBOSE_PRINT(" [RCP] Checksum verification failed\n");
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
        VERBOSE_PRINT("  [TCP %x] TIME_WAIT expired, connection closed\n", peer->sender.local_addr);
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
    VERBOSE_PRINT("  [TCP %x] Sent SYN, entering SYN_SENT state\n", peer->sender.local_addr);

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
            VERBOSE_PRINT("  [TCP %x] Connection attempt aborted\n", peer->sender.local_addr);
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
 * Return the number of bytes available to read from the receiver
 *
 * @param peer The TCP peer to check
 * @return The number of bytes available to read
 */
static inline size_t tcp_bytes_available(tcp_peer_t *peer) {
    return bs_bytes_available(&peer->receiver.writer);
}

/**
 * Check if the TCP connection has enough space to write new data into
 *
 * @param peer The TCP peer to check
 * @return True if there is enough space, false otherwise
 */
static inline bool tcp_has_space(tcp_peer_t *peer) {
    return bs_remaining_capacity(&peer->sender.reader) > 0;
}

/**
 * Return the number of bytes available to write into the sender's bytestream
 *
 * @param peer The TCP peer to check
 * @return The remaining capacity of the sender's bytestream
 */
static inline size_t tcp_space_available(tcp_peer_t *peer) {
    return bs_remaining_capacity(&peer->sender.reader);
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

    // If in TIME_WAIT and timer has expired, close the connection
    if (peer->state == TCP_TIME_WAIT) {
        peer->state = TCP_CLOSED;
        bool timer_expired = timer_get_usec() >= peer->timeout_time_us;
        if (timer_expired) {
            VERBOSE_PRINT("  [TCP %x] TIME_WAIT expired, connection closed\n",
                          peer->sender.local_addr);
        }
        return timer_expired;
    }

    bool is_active = sender_active || receiver_active;
    if (!is_active) {
        peer->state = TCP_CLOSED;
        VERBOSE_PRINT("  [TCP %x] Connection is not active\n", peer->sender.local_addr);
    }
    return is_active;
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
        peer->segs_in_flight--;
    }
}