#pragma once

#include "bytestream.h"
#include "nrf.h"
#include "types.h"

/* Forward declarations for segment types */
typedef struct sender_segment sender_segment_t;
typedef struct receiver_segment receiver_segment_t;
typedef struct tcp_peer tcp_peer_t;

/* Function pointer type for transmitting segments back to sender */
typedef void (*receiver_transmit_fn_t)(tcp_peer_t *peer, receiver_segment_t *segment);

/* Receiver state structure */
typedef struct receiver {
    nrf_t *nrf;          /* Receiver's NRF interface (to receive segments) */
    bytestream_t writer; /* Receiver writes to it, app reads from it */

    char reasm_buffer[MAX_WINDOW_SIZE];  /* Buffer for reassembled data */
    bool reasm_bitmask[MAX_WINDOW_SIZE]; /* Bitmask to track received segments */

    uint32_t total_size; /* Total bytes received */
    bool syn_received;   /* Whether a SYN has been received */
    bool fin_received;   /* Whether a FIN has been received */

    receiver_transmit_fn_t transmit; /* Callback to send ACKs to the remote peer */
    tcp_peer_t *peer;                /* Pointer to the TCP peer containing this receiver */
} receiver_t;

/* Forward declarations for functions */
static inline receiver_t receiver_init(nrf_t *nrf, receiver_transmit_fn_t transmit,
                                       tcp_peer_t *peer);
static inline void reasm_insert(receiver_t *receiver, size_t first_idx, char *data, size_t len,
                                bool is_last);
static inline uint16_t reasm_bytes_pending(receiver_t *receiver);
static inline void recv_process_segment(receiver_t *receiver, sender_segment_t *segment);

/**
 * Initialize the receiver with default state
 *
 * @param nrf The NRF interface for receiving data
 * @param transmit Function to transmit ACKs back to the sender
 * @param peer Pointer to the TCP peer containing this receiver
 * @return Initialized receiver structure
 */
static inline receiver_t receiver_init(nrf_t *nrf, receiver_transmit_fn_t transmit,
                                       tcp_peer_t *peer) {
    receiver_t receiver = {
        .nrf = nrf,
        .writer = bs_init(),
        .reasm_buffer = {0},
        .reasm_bitmask = {0},
        .total_size = 0,
        .fin_received = false,
        .syn_received = false,
        .transmit = transmit,
        .peer = peer,
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
        return;
    }

    // Calculate the usable portion of the segment
    const size_t first_inserted_idx = MAX(first_idx, first_unassembled_idx);
    const size_t last_inserted_idx = MIN(first_idx + len, first_unacceptable_idx);

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
 * Process a segment from the sender
 *
 * @param receiver The receiver to process the segment
 * @param segment The segment to process
 */
static inline void recv_process_segment(receiver_t *receiver, sender_segment_t *segment) {
    assert(receiver);
    assert(segment);

    // Handle SYN flag
    if (!receiver->syn_received) {
        if (segment->is_syn) {
            receiver->syn_received = true;
        } else {
            // Ignore segments before SYN is received
            return;
        }
    }

    // Process the segment data through the reassembler
    // If the SYN flag is set, the data starts at index 1
    uint16_t data_offset = segment->is_syn ? 1 : 0;
    uint16_t first_stream_idx = data_offset + segment->seqno - 1;

    reasm_insert(receiver, first_stream_idx, segment->payload, segment->len, segment->is_fin);

    // Calculate ackno and window size for the ACK
    // Add 1 to ackno if FIN has been processed
    uint16_t fin_offset = bs_writer_finished(&receiver->writer) ? 1 : 0;

    // Add one to stream index to account for the SYN
    uint16_t ackno = fin_offset + bs_bytes_written(&receiver->writer) + 1;

    // Update advertised window size
    uint32_t window_size = MIN(bs_remaining_capacity(&receiver->writer), MAX_WINDOW_SIZE);

    // Send an ACK for all processed data
    receiver_segment_t ack = {
        .ackno = ackno,
        .is_ack = true,
        .window_size = window_size,
    };

    receiver->transmit(receiver->peer, &ack);
}