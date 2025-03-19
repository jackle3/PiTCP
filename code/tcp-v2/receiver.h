#pragma once

#include "bytestream.h"
#include "types.h"

#define ABS(x) ((x) < 0 ? -(x) : (x))

// The threshold between the received and current seqno where we'll reject the message
#define SEQNO_REJECT_DELTA 3000

/********* TYPES *********/

// Receiver's maximum advertised window size
#define MAX_WINDOW_SIZE 1024

/* Receiver state structure */
typedef struct receiver {
    bytestream_t writer;             /* Receiver writes to it, app reads from it */
    uint8_t local_addr;              /* Local RCP address */
    uint8_t remote_addr;             /* Remote RCP address */
    char reasm_buffer[BS_CAPACITY];  /* Buffer for reassembled data */
    char reasm_bitmask[BS_CAPACITY]; /* Bitmask to track received segments */
    uint32_t total_size;             /* Total bytes received */
    uint32_t next_seqno;             /* Next expected sequence number */
    uint16_t window_size;            /* Advertised window size */
    bool syn_received;               /* Whether a SYN has been received */
    bool fin_received;               /* Whether a FIN has been received */
    uint32_t latest_seqno_in_reasm;  /* Latest seqno in reassembler */
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
    receiver_t receiver = {.writer = bs_init(),
                           .reasm_buffer = {0},
                           .reasm_bitmask = {0},
                           .total_size = 0,
                           .next_seqno = 0,
                           .window_size = MAX_WINDOW_SIZE,
                           .fin_received = false,
                           .syn_received = false,
                           .local_addr = local_addr,
                           .remote_addr = remote_addr,
                           .latest_seqno_in_reasm = 0};
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
        printk("    [REASM] Received FIN segment: first_idx %u, len %u\n", first_idx, len);
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

    DEBUG_PRINT(
        "    [REASM] Inserting segment %u to %u with length %u: first idx: %u, len: %u, available "
        "space: %u, first_unassembled_idx: %u, "
        "first_unacceptable_idx: %u\n",
        first_inserted_idx, last_inserted_idx, last_inserted_idx - first_inserted_idx, first_idx,
        len, available_space, first_unassembled_idx, first_unacceptable_idx);

    // Insert into reassembler if the substring is non-zero length
    if (first_inserted_idx < last_inserted_idx) {
        size_t insert_idx = first_inserted_idx - first_unassembled_idx;
        size_t copy_len = last_inserted_idx - first_inserted_idx;

        // Copy the usable substring into the reassembler buffer
        memcpy(receiver->reasm_buffer + insert_idx, data + first_inserted_idx - first_idx,
               copy_len);

        // Update the latest sequence number in reassembler
        if (first_inserted_idx + copy_len - 1 > receiver->latest_seqno_in_reasm) {
            receiver->latest_seqno_in_reasm = first_inserted_idx + copy_len - 1;
        }

        // Mark the bytes as received
        memset(receiver->reasm_bitmask + insert_idx, 1, copy_len);
    }

    // Push any contiguous bytes in reassembler buffer to the writer
    uint16_t index_to_push = 0;
    while (index_to_push < sizeof(receiver->reasm_buffer) &&
           receiver->reasm_bitmask[index_to_push] == 1) {
        index_to_push++;
    }

    DEBUG_PRINT("    [REASM] Pushing %u bytes to the writer\n", index_to_push);

    // Push contiguous bytes to the writer if any exist
    if (index_to_push > 0) {
        // Write the contiguous data to the bytestream
        bs_write(&receiver->writer, receiver->reasm_buffer, index_to_push);

        int remaining_sz = sizeof(receiver->reasm_buffer) - index_to_push;

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
    for (size_t i = 0; i < sizeof(receiver->reasm_buffer); i++) {
        if (receiver->reasm_bitmask[i] == 1) {
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

    // Handle SYN flag - initialize the stream
    if (segment->is_syn) {
        receiver->syn_received = true;
    }

    // Only process the segment if we've received a SYN
    if (!receiver->syn_received) {
        // Ignore segments before SYN is received
        DEBUG_PRINT("    [RECV] Missing SYN, ignoring segment %u to %u with length %u\n",
                    segment->seqno, segment->seqno + segment->len, segment->len);
        return NULL;
    }

    // We don't not need to reply to empty segments
    if (!segment->is_syn && !segment->is_fin && !segment->len) {
        DEBUG_PRINT("    [RECV] Ignoring empty segment\n");
        return NULL;
    }

    // Calculate the stream index for the first byte
    uint32_t checkpoint = bs_bytes_written(&receiver->writer);
    uint32_t syn_offset = segment->is_syn ? 1 : 0;
    uint32_t first_idx = syn_offset + unwrap_seqno(segment->seqno, checkpoint) - 1;

    // === FIN VALIDATION ===
    // Verify FIN flags to protect against corrupted packets
    if (segment->is_fin) {
        // Calculate sequence delta to check if this FIN is reasonable
        int32_t seqno_delta = (int32_t)first_idx - (int32_t)checkpoint;

        // Validate sequence number - FIN should not be extremely far from expected
        if (ABS(seqno_delta) > SEQNO_REJECT_DELTA) {
            printk(
                "    [RECV] Ignoring suspicious FIN with distant seqno %u (expected: %u, delta: "
                "%d)\n",
                segment->seqno, wrap_seqno(checkpoint), seqno_delta);

            return NULL;
        }

        // Add debug info for all FINs
        printk("    [RECV] Processing FIN segment: seqno=%u (idx=%u), received=%u bytes\n",
               segment->seqno, first_idx, bs_bytes_written(&receiver->writer));
    }

    // Insert the payload into the reassembler
    size_t payload_len = segment->len;
    if (segment->is_syn)
        payload_len--;
    if (segment->is_fin)
        payload_len--;
    reasm_insert(receiver, first_idx, segment->payload, payload_len, segment->is_fin);

    // Create and return the ACK response
    static receiver_segment_t ack_response = {0};
    ack_response.is_ack = true;
    ack_response.window_size = MIN(bs_remaining_capacity(&receiver->writer), MAX_WINDOW_SIZE);

    uint32_t fin_offset = bs_writer_finished(&receiver->writer) ? 1 : 0;
    uint32_t ackno = 1 + bs_bytes_written(&receiver->writer) + fin_offset;  // +1 for SYN
    ack_response.ackno = wrap_seqno(ackno);
    receiver->next_seqno = ackno;

    DEBUG_PRINT("    [RECV] Sending ACK: ackno %u (abs %u), window size %u, bytes_written %u\n",
                ack_response.ackno, ackno, ack_response.window_size,
                bs_bytes_written(&receiver->writer));

    return &ack_response;
}