#pragma once

#include "bytestream.h"
#include "types.h"

/********* TYPES *********/

/* Receiver state structure */
typedef struct receiver {
    bytestream_t writer;                 /* Receiver writes to it, app reads from it */
    uint8_t local_addr;                  /* Local RCP address */
    uint8_t remote_addr;                 /* Remote RCP address */
    char reasm_buffer[MAX_WINDOW_SIZE];  /* Buffer for reassembled data */
    bool reasm_bitmask[MAX_WINDOW_SIZE]; /* Bitmask to track received segments */
    uint32_t total_size;                 /* Total bytes received */
    uint32_t next_seqno;                 /* Next expected sequence number */
    uint16_t window_size;                /* Advertised window size */
    bool syn_received;                   /* Whether a SYN has been received */
    bool fin_received;                   /* Whether a FIN has been received */
} receiver_t;

/********* RECEIVER *********/

/**
 * Initialize the receiver with default state
 *
 * @param local_addr Local RCP address
 * @param remote_addr Remote RCP address
 * @return Initialized receiver structure
 */
static inline receiver_t receiver_init(uint8_t local_addr, uint8_t remote_addr) {
    receiver_t receiver = {
        .writer = bs_init(),
        .reasm_buffer = {0},
        .reasm_bitmask = {0},
        .total_size = 0,
        .next_seqno = 0,
        .window_size = MAX_WINDOW_SIZE,
        .fin_received = false,
        .syn_received = false,
        .local_addr = local_addr,
        .remote_addr = remote_addr,
    };
    return receiver;
}

/**
 * Insert a segment into the reassembler
 *
 * @param receiver The receiver to insert the segment into
 * @param first_idx The index of the first byte in the segment
 * @param data The data to insert into the reassembler
 * @param len The length of the data to insert
 * @param is_last Whether the segment is the last segment (FIN)
 */
static inline void reasm_insert(receiver_t *receiver, size_t first_idx, char *data, size_t len,
                                bool is_last) {
    assert(receiver);
    assert(data);

    // If the segment is a FIN, update total size and set fin flag
    if (is_last) {
        receiver->total_size = first_idx + len;
        receiver->fin_received = true;
    }

    const size_t available_space = bs_remaining_capacity(&receiver->writer);
    const size_t first_unassembled_idx = bs_bytes_written(&receiver->writer);
    const size_t first_unacceptable_idx = first_unassembled_idx + available_space;

    // If the segment is too far ahead, ignore it
    if (first_idx >= first_unacceptable_idx) {
        DEBUG_PRINT("    [REASM] Ignoring segment %u to %u with length %u\n", first_idx,
                    first_idx + len, len);
        return;
    }

    // Calculate the usable portion of the segment
    const size_t first_inserted_idx = MAX(first_idx, first_unassembled_idx);
    const size_t last_inserted_idx = MIN(first_idx + len, first_unacceptable_idx);

    DEBUG_PRINT("    [REASM] Inserting segment %u to %u with length %u\n", first_inserted_idx,
                last_inserted_idx, last_inserted_idx - first_inserted_idx);

    // Insert into reassembler if the substring is non-zero length
    if (first_inserted_idx < last_inserted_idx) {
        size_t insert_idx = first_inserted_idx - first_unassembled_idx;
        size_t copy_len = last_inserted_idx - first_inserted_idx;

        // Copy the usable substring into the reassembler buffer
        memcpy(receiver->reasm_buffer + insert_idx, data + (first_inserted_idx - first_idx),
               copy_len);

        // Mark the bytes as received
        memset(receiver->reasm_bitmask + insert_idx, true, copy_len);
    }

    // Push any contiguous bytes in reassembler buffer to the writer
    uint16_t index_to_push = 0;
    while (index_to_push < MAX_WINDOW_SIZE && receiver->reasm_bitmask[index_to_push]) {
        index_to_push++;
    }

    DEBUG_PRINT("    [REASM] Pushing %u bytes to the writer\n", index_to_push);

    // Push contiguous bytes to the writer if any exist
    if (index_to_push > 0) {
        bs_write(&receiver->writer, receiver->reasm_buffer, index_to_push);

        int remaining_sz = MAX_WINDOW_SIZE - index_to_push;

        // Shift the remaining data and bitmask to the beginning
        if (remaining_sz > 0) {
            memmove(receiver->reasm_buffer, receiver->reasm_buffer + index_to_push, remaining_sz);

            memmove(receiver->reasm_bitmask, receiver->reasm_bitmask + index_to_push, remaining_sz);
        }

        // Clear the now-empty portion of the buffer and bitmask
        memset(receiver->reasm_buffer + remaining_sz, 0, index_to_push);
        memset(receiver->reasm_bitmask + remaining_sz, 0, index_to_push);
    }

    // Close the bytestream once all data has been received
    if (receiver->fin_received && bs_bytes_written(&receiver->writer) == receiver->total_size) {
        bs_end_input(&receiver->writer);
    }
}

/**
 * Get the number of bytes pending in the reassembler
 *
 * @param receiver The receiver to check
 * @return The number of bytes pending in the reassembler
 */
static inline uint16_t reasm_bytes_pending(receiver_t *receiver) {
    assert(receiver);

    uint16_t bytes_pending = 0;
    for (size_t i = 0; i < MAX_WINDOW_SIZE; i++) {
        if (receiver->reasm_bitmask[i]) {
            bytes_pending++;
        }
    }
    return bytes_pending;
}

/**
 * Process a segment from the sender and generate an ACK response if needed
 *
 * @param receiver The receiver to process the segment
 * @param segment The segment to process
 * @return A pointer to the response segment if an ACK is needed, NULL otherwise
 */
static inline receiver_segment_t *receiver_process_segment(receiver_t *receiver,
                                                           sender_segment_t *segment) {
    assert(receiver);
    assert(segment);

    static receiver_segment_t ack_response = {0};
    bool send_ack = false;

    // Handle SYN flag - important for three-way handshake
    if (segment->is_syn) {
        if (!receiver->syn_received) {
            receiver->syn_received = true;
            receiver->next_seqno = segment->seqno + 1;  // SYN consumes a sequence number

            // Don't need to process data for a pure SYN (it has no payload)
            if (segment->len == 0) {
                // Send an ACK for the SYN
                ack_response.ackno = receiver->next_seqno;
                ack_response.is_ack = true;
                ack_response.window_size = bs_remaining_capacity(&receiver->writer);

                DEBUG_PRINT("    [RECV] Sending ACK for SYN with ackno %u and window size %u\n",
                            ack_response.ackno, ack_response.window_size);

                return &ack_response;
            }
            // If SYN has payload, continue processing below
        } else if (segment->seqno < receiver->next_seqno - 1) {
            // This is a duplicate SYN, just ACK what we've received so far
            ack_response.ackno = receiver->next_seqno;
            ack_response.is_ack = true;
            ack_response.window_size = bs_remaining_capacity(&receiver->writer);

            DEBUG_PRINT("    [RECV] Duplicate SYN, sending ACK with ackno %u\n",
                        ack_response.ackno);
            return &ack_response;
        }
    } else if (!receiver->syn_received) {
        // Ignore segments before SYN is received
        DEBUG_PRINT("    [RECV] Missing SYN, ignoring segment %u to %u with length %u\n",
                    segment->seqno, segment->seqno + segment->len, segment->len);
        return NULL;
    }

    // Check if this segment is in sequence
    if (segment->seqno < receiver->next_seqno) {
        // This is a duplicate segment or partially overlapping with data we already received

        // Calculate the overlap (if any)
        uint32_t overlap_start = segment->seqno;
        uint32_t overlap_end = MIN(segment->seqno + segment->len, receiver->next_seqno);

        // If this segment is completely duplicate, just ACK what we've received
        if (segment->seqno + segment->len <= receiver->next_seqno) {
            // Send acknowledgment for the data we've already received
            ack_response.ackno = receiver->next_seqno;
            ack_response.is_ack = true;
            ack_response.window_size = bs_remaining_capacity(&receiver->writer);

            DEBUG_PRINT("    [RECV] Duplicate segment, sending ACK with ackno %u\n",
                        ack_response.ackno);
            return &ack_response;
        }

        // If it's partially overlapping, only process the new part
        uint32_t new_start = receiver->next_seqno;
        uint32_t new_size = segment->len - (new_start - segment->seqno);

        // Process the new part through the reassembler
        reasm_insert(receiver,
                     new_start - 1,  // Subtract 1 to account for the SYN
                     segment->payload + (new_start - segment->seqno), new_size, segment->is_fin);

        send_ack = true;
    } else if (segment->seqno == receiver->next_seqno) {
        // This segment is the next one we're expecting - perfect!

        // Process the segment data through the reassembler
        reasm_insert(receiver,
                     segment->seqno - 1,  // Subtract 1 to account for the SYN
                     segment->payload, segment->len, segment->is_fin);

        // Update next expected sequence number
        receiver->next_seqno = segment->seqno + segment->len;

        // If FIN flag is set, we also consume a sequence number for it
        if (segment->is_fin) {
            receiver->next_seqno++;
        }

        send_ack = true;
    } else {
        // This segment has a gap - we're missing some data
        // We'll still buffer it in the reassembler if possible

        // Process the segment data through the reassembler
        reasm_insert(receiver,
                     segment->seqno - 1,  // Subtract 1 to account for the SYN
                     segment->payload, segment->len, segment->is_fin);

        send_ack = true;
    }

    // Generate ACK if needed
    if (send_ack) {
        // Update advertised window size
        uint32_t window_size = bs_remaining_capacity(&receiver->writer);
        receiver->window_size = MIN(window_size, MAX_WINDOW_SIZE);

        // Send an ACK for all processed data
        ack_response.ackno = receiver->next_seqno;
        ack_response.is_ack = true;
        ack_response.window_size = receiver->window_size;

        DEBUG_PRINT("    [RECV] Sending ACK for segment with ackno %u and window size %u\n",
                    ack_response.ackno, ack_response.window_size);

        return &ack_response;
    }

    return NULL;
}