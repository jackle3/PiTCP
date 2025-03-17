#pragma once

#include <stdbool.h>

#include "rcp-datagram.h"

typedef struct receiver_segment {
    uint16_t ackno;        // Sequence number of the ACK
    bool is_ack;           // Whether the segment is an ACK
    uint16_t window_size;  // Advertised window size
} receiver_segment_t;

typedef struct sender_segment {
    uint16_t seqno;
    bool is_syn;  // Whether the segment is a SYN
    bool is_fin;  // Whether the segment is a FIN
    size_t len;   // Length of the payload
    uint8_t payload[RCP_MAX_PAYLOAD];
} sender_segment_t;

typedef struct tcp_segment {
    sender_segment_t sender_segment;
    receiver_segment_t receiver_segment;
    bool has_sender_segment;    // Whether this segment contains sender data
    bool has_receiver_segment;  // Whether this segment contains receiver data
} tcp_segment_t;

/**
 * Unwrap a 16-bit sequence number to a 32-bit absolute sequence number
 *
 * @param seqno The 16-bit sequence number to unwrap
 * @param checkpoint A recent absolute sequence number to use as a reference
 * @return The unwrapped 32-bit absolute sequence number
 */
static inline uint32_t unwrap_seqno(uint16_t seqno, uint32_t checkpoint) {
    const uint32_t WRAP_RANGE = 65536;  // 2^16

    // Calculate the offset from the checkpoint
    uint32_t checkpoint_wrap = checkpoint & ~0xFFFF;  // Clear the lower 16 bits

    // Calculate three possible interpretations: same wrap, next wrap, or previous wrap
    uint32_t same_wrap = checkpoint_wrap | seqno;
    uint32_t next_wrap = same_wrap + WRAP_RANGE;
    uint32_t prev_wrap = (same_wrap >= WRAP_RANGE) ? (same_wrap - WRAP_RANGE) : same_wrap;

    // Choose the interpretation that minimizes the distance to the checkpoint
    uint32_t dist_same =
        (same_wrap >= checkpoint) ? (same_wrap - checkpoint) : (checkpoint - same_wrap);
    uint32_t dist_next =
        (next_wrap >= checkpoint) ? (next_wrap - checkpoint) : (checkpoint - next_wrap);
    uint32_t dist_prev =
        (prev_wrap >= checkpoint) ? (prev_wrap - checkpoint) : (checkpoint - prev_wrap);

    if (dist_same <= dist_next && dist_same <= dist_prev) {
        return same_wrap;
    } else if (dist_next <= dist_prev) {
        return next_wrap;
    } else {
        return prev_wrap;
    }
}

/**
 * Wrap a 32-bit absolute sequence number to a 16-bit sequence number for the header
 *
 * @param abs_seqno The 32-bit absolute sequence number to wrap
 * @return The wrapped 16-bit sequence number
 */
static inline uint16_t wrap_seqno(uint32_t abs_seqno) { return (uint16_t)(abs_seqno & 0xFFFF); }