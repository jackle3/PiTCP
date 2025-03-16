#pragma once

#include "bytestream.h"
#include "types.h"

/********* TYPES *********/

/* Initial window size and timeout constants */
#define INITIAL_WINDOW_SIZE 256
#define MS_TO_US(ms) ((ms) * 1000)
#define MIN_CWND (4 * RCP_MAX_PAYLOAD)        /* Minimum congestion window size */
#define MAX_CWND (64 * RCP_MAX_PAYLOAD)       /* Maximum congestion window size */
#define CWND_THRESHOLD (16 * RCP_MAX_PAYLOAD) /* Threshold to exit slow start */

/* Sender state structure */
typedef struct sender {
    bytestream_t reader;  /* App writes data to it, sender reads from it */
    uint8_t local_addr;   /* Local RCP address */
    uint8_t remote_addr;  /* Remote RCP address */
    uint16_t next_seqno;  /* Next sequence number to send */
    uint16_t acked_seqno; /* Sequence number of the highest acked segment */
    uint16_t window_size; /* Receiver's advertised window size */

    /* Congestion control fields */
    uint16_t cwnd;              /* Congestion window size in bytes */
    uint8_t dup_ack_count;      /* Count of duplicate ACKs */
    bool in_slow_start;         /* Whether in slow start or congestion avoidance */
    uint32_t last_send_time;    /* Time of last segment sent */
    uint32_t min_send_interval; /* Minimum interval between sends */
} sender_t;

/********* SENDER *********/

/**
 * Initialize the sender with default state
 *
 * @param local_addr Local RCP address
 * @param remote_addr Remote RCP address
 * @return Initialized sender structure
 */
static inline sender_t sender_init(uint8_t local_addr, uint8_t remote_addr) {
    sender_t sender = {
        .reader = bs_init(),
        .next_seqno = 0,
        .acked_seqno = 0,
        .window_size = INITIAL_WINDOW_SIZE,
        .local_addr = local_addr,
        .remote_addr = remote_addr,

        /* Initialize congestion control */
        .cwnd = MIN_CWND, /* Start with 2 segments */
        .dup_ack_count = 0,
        .in_slow_start = true,
        .last_send_time = 0,
        .min_send_interval = MS_TO_US(1) /* 1ms initial pacing */
    };
    return sender;
}

/**
 * Create a segment to be sent
 *
 * @param sender The sender to create the segment for
 * @param len The maximum length of the data to send
 * @return The created segment
 */
static inline sender_segment_t make_segment(sender_t *sender, size_t len) {
    assert(sender);

    sender_segment_t seg = {
        .len = 0,
        .seqno = sender->next_seqno,
        .is_syn = (sender->next_seqno == 0),
        .is_fin = false,
    };

    // Determine how many bytes to send (limit by max payload and requested length)
    size_t bytes_to_send = MIN(RCP_MAX_PAYLOAD, len);
    if (bytes_to_send > 0) {
        // Read data from bytestream into segment payload
        seg.len = bs_read(&sender->reader, seg.payload, bytes_to_send);
    }

    // Check if this is the FIN segment
    seg.is_fin =
        bs_reader_finished(&sender->reader) && (bytes_to_send == 0 || seg.len < bytes_to_send);

    return seg;
}

/**
 * Update sender state after a segment has been sent
 *
 * @param sender The sender to update
 * @param segment The segment that was sent
 * @param current_time_us Current time in microseconds
 * @return True if state updated successfully
 */
static inline bool sender_segment_sent(sender_t *sender, sender_segment_t *segment,
                                       uint32_t current_time_us) {
    assert(sender);
    assert(segment);

    // Only update sequence number for segments with data, SYN, or FIN
    // and only if the segment is in the future (seqno is past what we've sent)
    if ((segment->len > 0 || segment->is_syn || segment->is_fin) &&
        segment->seqno >= sender->next_seqno) {
        // Update next sequence number
        sender->next_seqno = segment->seqno + segment->len;

        // SYN and FIN take up one sequence number each
        if (segment->is_syn || segment->is_fin) {
            sender->next_seqno++;
        }

        // Update last send time
        sender->last_send_time = current_time_us;
    }

    return true;
}

/**
 * Check if it's too soon to send another segment
 *
 * @param sender The sender to check
 * @param current_time_us Current time in microseconds
 * @return True if we should wait, false if ok to send
 */
static inline bool sender_should_wait(sender_t *sender, uint32_t current_time_us) {
    assert(sender);

    return (current_time_us < sender->last_send_time + sender->min_send_interval);
}

/**
 * Process a reply from the receiver
 *
 * @param sender The sender to process the reply for
 * @param reply The reply segment from the receiver
 * @return A pointer to a segment that should be retransmitted, or NULL if none
 */
static inline void sender_process_ack(sender_t *sender, receiver_segment_t *reply) {
    assert(sender);
    assert(reply);

    if (reply->is_ack) {
        // Validate ACK number doesn't exceed what we've sent
        if (reply->ackno > sender->next_seqno) {
            return;
        }

        if (reply->ackno > sender->acked_seqno) {
            // New data acknowledged
            uint16_t bytes_acked = reply->ackno - sender->acked_seqno;
            sender->acked_seqno = reply->ackno;

            // Update congestion window
            if (sender->in_slow_start) {
                // Exponential increase during slow start
                sender->cwnd += MIN(bytes_acked, RCP_MAX_PAYLOAD);

                // Exit slow start if cwnd exceeds threshold
                if (sender->cwnd >= CWND_THRESHOLD) {
                    sender->in_slow_start = false;
                }
            } else {
                // Additive increase during congestion avoidance - about 1 segment per RTT
                // printk("Adding %u to cwnd\n", (RCP_MAX_PAYLOAD * bytes_acked) / sender->cwnd);
                sender->cwnd++;
            }

            // Cap the congestion window to avoid overflow
            if (sender->cwnd > MAX_CWND) {
                sender->cwnd = MAX_CWND;
            }

            // Reset duplicate ACK counter
            sender->dup_ack_count = 0;

            // Allow sending more frequently now
            sender->min_send_interval = MAX(sender->min_send_interval / 2, MS_TO_US(0.5));
        } else if (reply->ackno == sender->acked_seqno) {
            // Duplicate ACK received
            sender->dup_ack_count++;

            // Fast retransmit after 3 duplicate ACKs
            if (sender->dup_ack_count == 3) {
                // Cut congestion window in half
                sender->cwnd = MAX(sender->cwnd / 2, MIN_CWND);
                sender->in_slow_start = false;

                // Reset the counter - we'll handle actual retransmit in tcp.h
                sender->dup_ack_count = 0;
            }
        }
    }

    // Update window size from receiver
    sender->window_size = reply->window_size;
}

/**
 * Generate the next segment to send if any
 *
 * @param sender The sender to generate a segment from
 * @param current_time_us Current time in microseconds
 * @return A pointer to the generated segment, or NULL if none
 */
static inline sender_segment_t *sender_generate_segment(sender_t *sender,
                                                        uint32_t current_time_us) {
    assert(sender);

    static sender_segment_t next_segment;

    DEBUG_PRINT(" [SENDER] Generating segment\n");
    DEBUG_PRINT("      - sender->next_seqno: %u\n", sender->next_seqno);
    DEBUG_PRINT("      - bs_reader_finished(&sender->reader): %u\n",
                bs_reader_finished(&sender->reader));
    DEBUG_PRINT("      - bs_bytes_popped(&sender->reader): %u\n", bs_bytes_popped(&sender->reader));
    DEBUG_PRINT("      - bs_bytes_available(&sender->reader): %u\n",
                bs_bytes_available(&sender->reader));

    // Don't send if too soon after last send
    if (sender_should_wait(sender, current_time_us)) {
        return NULL;
    }

    // Calculate bytes in flight
    uint16_t bytes_in_flight = sender->next_seqno - sender->acked_seqno;

    // Don't send if we've hit congestion window limit
    if (bytes_in_flight >= sender->cwnd) {
        return NULL;
    }

    // Don't send if receiver window is full
    if (bytes_in_flight >= sender->window_size) {
        return NULL;
    }

    // If FIN has been sent, no more data can be pushed
    if (bs_reader_finished(&sender->reader) &&
        (sender->next_seqno > bs_bytes_popped(&sender->reader) + 1)) {
        // The seqno of FIN is `1 + bytes_popped`, so if next_seqno is greater, we've sent FIN
        return NULL;
    }

    // Determine remaining window space
    uint16_t effective_window = MIN(sender->cwnd, sender->window_size);
    uint16_t remaining_window = effective_window - bytes_in_flight;

    // Edge case: if effective window is 0, send probe segment for window update
    if (effective_window == 0 && sender->window_size == 0) {
        next_segment = make_segment(sender, 0);
        return &next_segment;
    }

    // Send data if available in the bytestream
    if (bs_bytes_available(&sender->reader) && remaining_window > 0) {
        next_segment = make_segment(sender, remaining_window);
        return &next_segment;
    } else if (bs_reader_finished(&sender->reader)) {
        // If bytestream is finished and we haven't sent FIN yet, send it
        next_segment.seqno = sender->next_seqno;
        next_segment.is_syn = false;
        next_segment.is_fin = true;
        next_segment.len = 0;
        return &next_segment;
    }

    return NULL;
}

/**
 * Handle a retransmission event
 *
 * @param sender The sender to update
 * @param seqno The sequence number being retransmitted
 * @param current_time_us Current time in microseconds
 */
static inline void sender_handle_retransmit(sender_t *sender, uint16_t seqno) {
    assert(sender);

    // Reduce congestion window
    sender->cwnd = MAX(sender->cwnd / 2, MIN_CWND);
    sender->in_slow_start = false;

    // Increase pacing interval to slow down sending
    sender->min_send_interval = MIN(sender->min_send_interval * 2, MS_TO_US(10));
}

/**
 * Check if the sender has completed sending all data
 *
 * @param sender The sender to check
 * @return True if all data has been sent and acknowledged
 */
static inline bool sender_is_done(sender_t *sender) {
    assert(sender);

    // Sender is done when all data has been acknowledged,
    // including the FIN if the stream is finished
    if (bs_reader_finished(&sender->reader)) {
        // Add 1 for the FIN
        return sender->acked_seqno >= bs_bytes_popped(&sender->reader) + 1;
    }

    // If stream not finished, sender is only done if there's no data pending
    return bs_bytes_available(&sender->reader) == 0 && sender->acked_seqno == sender->next_seqno;
}

/**
 * Get the current congestion window information
 *
 * @param sender The sender to check
 * @param cwnd_out Pointer to store the congestion window
 * @param bytes_in_flight_out Pointer to store bytes in flight
 */
static inline void sender_get_cwnd_info(sender_t *sender, uint16_t *cwnd_out,
                                        uint16_t *bytes_in_flight_out) {
    assert(sender);

    if (cwnd_out) {
        *cwnd_out = sender->cwnd;
    }

    if (bytes_in_flight_out) {
        *bytes_in_flight_out = sender->next_seqno - sender->acked_seqno;
    }
}