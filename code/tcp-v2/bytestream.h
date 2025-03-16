#pragma once

#include <stdbool.h>

#include "rpi.h"

/**
 * Bytestream structure for managing circular buffer of bytes
 *
 * The bytestream connects the TCP sender and receiver to their application interfaces.
 *
 * sender's bytestream:
 * - The application writes data to the bytestream
 * - The sender reads data from the bytestream and sends it via NRF
 *
 * receiver's bytestream:
 * - When the receiver receives a packet via NRF, the receiver writes the data to the bytestream
 * - The application reads data from the bytestream
 */

/* Define MIN/MAX macros */
#define MIN(a, b) ((a) < (b) ? (a) : (b))
#define MAX(a, b) ((a) > (b) ? (a) : (b))

/* Buffer capacity constants */
#define MAX_WINDOW_SIZE 512
#define BS_CAPACITY MAX_WINDOW_SIZE

/**
 * Bytestream structure - circular buffer implementation
 */
typedef struct bytestream {
    uint8_t buffer[BS_CAPACITY]; /* Circular buffer */
    size_t read_pos;             /* Position for next read operation */
    size_t write_pos;            /* Position for next write operation */
    size_t bytes_available;      /* Number of bytes available to read */
    bool eof;                    /* Whether the stream has reached end-of-file */
    size_t bytes_written;        /* Total number of bytes written to the stream */
} bytestream_t;

/* Forward declarations for all functions */
static inline bytestream_t bs_init(void);
static inline size_t bs_bytes_available(const bytestream_t *bs);
static inline size_t bs_remaining_capacity(const bytestream_t *bs);
static inline size_t bs_peek(const bytestream_t *bs, uint8_t *data, size_t len);
static inline size_t bs_read(bytestream_t *bs, uint8_t *data, size_t len);
static inline size_t bs_write(bytestream_t *bs, const uint8_t *data, size_t len);
static inline size_t bs_bytes_written(const bytestream_t *bs);
static inline size_t bs_bytes_popped(const bytestream_t *bs);
static inline bool bs_reader_finished(const bytestream_t *bs);
static inline bool bs_writer_finished(const bytestream_t *bs);
static inline void bs_end_input(bytestream_t *bs);

/**
 * Initialize a bytestream
 *
 * @return Initialized bytestream structure
 */
static inline bytestream_t bs_init(void) {
    bytestream_t bs;
    memset(bs.buffer, 0, BS_CAPACITY);
    bs.read_pos = 0;
    bs.write_pos = 0;
    bs.bytes_available = 0;
    bs.bytes_written = 0;
    bs.eof = false;
    return bs;
}

/**
 * Get number of bytes available for reading
 *
 * @param bs Pointer to the bytestream
 * @return Number of bytes available to read
 */
static inline size_t bs_bytes_available(const bytestream_t *bs) {
    assert(bs);
    return bs->bytes_available;
}

/**
 * Get remaining capacity for writing data
 *
 * @param bs Pointer to the bytestream
 * @return Number of bytes that can be written before the buffer is full
 */
static inline size_t bs_remaining_capacity(const bytestream_t *bs) {
    assert(bs);
    return BS_CAPACITY - bs->bytes_available;
}

/**
 * Peek at data without removing it from the bytestream
 *
 * @param bs Pointer to the bytestream
 * @param data Buffer where the peeked data will be stored
 * @param len Maximum number of bytes to peek
 * @return Number of bytes actually peeked
 */
static inline size_t bs_peek(const bytestream_t *bs, uint8_t *data, size_t len) {
    assert(bs);
    assert(data);

    // Don't peek more than what's available
    size_t bytes_to_peek = MIN(len, bs_bytes_available(bs));
    if (bytes_to_peek == 0) {
        return 0;
    }

    // Handle buffer wraparound - may need to peek in two parts
    size_t first_chunk = BS_CAPACITY - bs->read_pos;
    if (bytes_to_peek <= first_chunk) {
        // Can peek all data in one chunk
        memcpy(data, bs->buffer + bs->read_pos, bytes_to_peek);
    } else {
        // Need to split the peek into two parts due to wraparound
        memcpy(data, bs->buffer + bs->read_pos, first_chunk);
        memcpy(data + first_chunk, bs->buffer, bytes_to_peek - first_chunk);
    }

    return bytes_to_peek;
}

/**
 * Read data from the bytestream and remove it
 *
 * @param bs Pointer to the bytestream
 * @param data Buffer where the read data will be stored
 * @param len Maximum number of bytes to read
 * @return Number of bytes actually read
 */
static inline size_t bs_read(bytestream_t *bs, uint8_t *data, size_t len) {
    assert(bs);
    assert(data);

    // First peek the data
    size_t bytes_read = bs_peek(bs, data, len);
    if (bytes_read == 0) {
        return 0;
    }

    // Update read position and bytes available
    bs->read_pos = (bs->read_pos + bytes_read) % BS_CAPACITY;
    bs->bytes_available -= bytes_read;

    return bytes_read;
}

/**
 * Write data to the bytestream
 *
 * @param bs Pointer to the bytestream
 * @param data Buffer containing data to write
 * @param len Number of bytes to write
 * @return Number of bytes actually written
 */
static inline size_t bs_write(bytestream_t *bs, const uint8_t *data, size_t len) {
    assert(bs);
    assert(data);

    // Don't write more than the available space
    size_t bytes_to_write = MIN(len, bs_remaining_capacity(bs));
    if (bytes_to_write == 0) {
        return 0;
    }

    // Handle buffer wraparound - may need to write in two parts
    size_t first_chunk = BS_CAPACITY - bs->write_pos;
    if (bytes_to_write <= first_chunk) {
        // Can write all data in one chunk
        memcpy(bs->buffer + bs->write_pos, data, bytes_to_write);
    } else {
        // Need to split the write into two parts due to wraparound
        memcpy(bs->buffer + bs->write_pos, data, first_chunk);
        memcpy(bs->buffer, data + first_chunk, bytes_to_write - first_chunk);
    }

    // Update write position and counters
    bs->write_pos = (bs->write_pos + bytes_to_write) % BS_CAPACITY;
    bs->bytes_available += bytes_to_write;
    bs->bytes_written += bytes_to_write;

    return bytes_to_write;
}

/**
 * Get total number of bytes written to the stream
 *
 * @param bs Pointer to the bytestream
 * @return Total number of bytes written
 */
static inline size_t bs_bytes_written(const bytestream_t *bs) {
    assert(bs);
    return bs->bytes_written;
}

/**
 * Get number of bytes that have been read (popped) from the stream
 *
 * @param bs Pointer to the bytestream
 * @return Number of bytes that have been read
 */
static inline size_t bs_bytes_popped(const bytestream_t *bs) {
    assert(bs);
    return bs->bytes_written - bs->bytes_available;
}

/**
 * Check if the reading stream is finished (i.e., all data has been read and EOF reached)
 *
 * @param bs Pointer to the bytestream
 * @return true if the reader has read all available data and EOF is set
 */
static inline bool bs_reader_finished(const bytestream_t *bs) {
    assert(bs);
    return bs->eof && bs->bytes_available == 0;
}

/**
 * Check if the writing stream is finished (i.e., EOF has been marked)
 *
 * @param bs Pointer to the bytestream
 * @return true if EOF has been marked on the stream
 */
static inline bool bs_writer_finished(const bytestream_t *bs) {
    assert(bs);
    return bs->eof;
}

/**
 * Mark the stream as finished (EOF)
 *
 * @param bs Pointer to the bytestream
 */
static inline void bs_end_input(bytestream_t *bs) {
    assert(bs);
    bs->eof = true;
}