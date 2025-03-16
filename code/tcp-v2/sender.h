#pragma once

#include "bytestream.h"
#include "types.h"

/********* TYPES *********/

/* Initial window size and timeout constants */
#define INITIAL_WINDOW_SIZE 1024

/* Sender state structure */
typedef struct sender {
    bytestream_t reader;  /* App writes data to it, sender reads from it */
    uint8_t local_addr;   /* Local RCP address */
    uint8_t remote_addr;  /* Remote RCP address */
    uint16_t next_seqno;  /* Next sequence number to send */
    uint16_t acked_seqno; /* Sequence number of the highest acked segment */
    uint16_t window_size; /* Receiver's advertised window size */
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
 * @return True if state updated successfully
 */
static inline bool sender_segment_sent(sender_t *sender, sender_segment_t *segment) {
    assert(sender);
    assert(segment);

    // Only update sequence number for segments with data, SYN, or FIN
    if (segment->len > 0 || segment->is_syn || segment->is_fin) {
        // Update next sequence number
        sender->next_seqno += segment->len;

        // SYN and FIN take up one sequence number each
        if (segment->is_syn || segment->is_fin) {
            sender->next_seqno++;
        }
    }

    return true;
}

/**
 * Process a reply from the receiver
 *
 * @param sender The sender to process the reply for
 * @param reply The reply segment from the receiver
 */
static inline void sender_process_ack(sender_t *sender, receiver_segment_t *reply) {
    assert(sender);
    assert(reply);

    if (reply->is_ack) {
        // Validate ACK number doesn't exceed what we've sent
        if (reply->ackno > sender->next_seqno) {
            return;
        }

        // Update highest acknowledged sequence number
        sender->acked_seqno = reply->ackno;
    }

    // Update window size from receiver
    sender->window_size = reply->window_size;
}

/**
 * Generate the next segment to send (if any)
 *
 * @param sender The sender to generate a segment from
 * @return A pointer to the generated segment, or NULL if none
 */
static inline sender_segment_t *sender_generate_segment(sender_t *sender) {
    assert(sender);

    static sender_segment_t next_segment;

    // If FIN has been sent, no more data can be pushed
    if (bs_reader_finished(&sender->reader) &&
        (sender->next_seqno > bs_bytes_popped(&sender->reader) + 1)) {
        // The seqno of FIN is `1 + bytes_popped`, so if next_seqno is greater, we've sent FIN
        return NULL;
    }

    // Edge case: if receiver window is 0, send a probe segment
    if (sender->window_size == 0) {
        // Send a zero-length segment to probe for window update
        next_segment = make_segment(sender, 0);
        return &next_segment;
    }

    // Check if receiver has enough space to receive more data
    uint32_t receiver_max_seqno = sender->acked_seqno + sender->window_size;
    if (receiver_max_seqno <= sender->next_seqno) {
        // No space in receiver window
        return NULL;
    }

    // Send data if available in the bytestream
    if (bs_bytes_available(&sender->reader)) {
        uint32_t remaining_space = receiver_max_seqno - sender->next_seqno;
        next_segment = make_segment(sender, remaining_space);
        return &next_segment;
    } else if (bs_reader_finished(&sender->reader) &&
               sender->next_seqno == bs_bytes_popped(&sender->reader)) {
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