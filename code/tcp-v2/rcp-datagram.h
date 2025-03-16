#pragma once

#include "rcp-header.h"

/* RCP Datagram structure
 * Contains both the header and payload of an RCP packet
 */
typedef struct rcp_datagram {
    rcp_header_t header;              /* RCP header (includes payload_len) */
    uint8_t payload[RCP_MAX_PAYLOAD]; /* Fixed-size payload buffer */
} rcp_datagram_t;

/* Forward declarations for inline functions */
static inline rcp_datagram_t rcp_datagram_init(void);
static inline int rcp_datagram_parse(rcp_datagram_t* dgram, const void* data, size_t length);
static inline int rcp_datagram_serialize(const rcp_datagram_t* dgram, void* data,
                                         size_t max_length);
static inline int rcp_datagram_set_payload(rcp_datagram_t* dgram, const void* data, size_t length);
static inline void rcp_datagram_compute_checksum(rcp_datagram_t* dgram);
static inline int rcp_datagram_verify_checksum(const rcp_datagram_t* dgram);

/* Initialize a new RCP datagram with default header values */
static inline rcp_datagram_t rcp_datagram_init(void) {
    rcp_datagram_t dgram;
    dgram.header = rcp_header_init();
    memset(dgram.payload, 0, RCP_MAX_PAYLOAD);
    return dgram;
}

/* Parse raw network data into an RCP datagram
 * Returns 1 on success, 0 on failure
 */
static inline int rcp_datagram_parse(rcp_datagram_t* dgram, const void* data, size_t length) {
    if (!dgram || !data || length < RCP_HEADER_LENGTH) {
        return 0;
    }

    // Parse header first
    rcp_header_parse(&dgram->header, data);

    // Use payload length from the header
    uint8_t payload_len = dgram->header.payload_len;

    // Validate payload length against actual received data
    if (length < RCP_HEADER_LENGTH + payload_len) {
        return 0;  // Incomplete data
    }

    if (payload_len > RCP_MAX_PAYLOAD) {
        return 0;  // Invalid payload length
    }

    // Copy payload if present
    if (payload_len > 0) {
        memcpy(dgram->payload, (const uint8_t*)data + RCP_HEADER_LENGTH, payload_len);
    }

    return 1;
}

/* Serialize an RCP datagram into network data
 * Returns number of bytes written, or -1 on error */
static inline int rcp_datagram_serialize(const rcp_datagram_t* dgram, void* data,
                                         size_t max_length) {
    if (!dgram || !data || max_length < RCP_HEADER_LENGTH) {
        return -1;
    }

    size_t total_length = RCP_HEADER_LENGTH + dgram->header.payload_len;
    if (max_length < total_length || total_length > RCP_TOTAL_SIZE) {
        return -1;  // Buffer too small or packet too large
    }

    // Serialize header
    rcp_header_serialize(&dgram->header, data);

    // Copy payload if present
    if (dgram->header.payload_len > 0) {
        memcpy((uint8_t*)data + RCP_HEADER_LENGTH, dgram->payload, dgram->header.payload_len);
    }

    return total_length;
}

/* Set the payload of an RCP datagram
 * Makes a copy of the provided data
 * Returns 0 on success, -1 on error */
static inline int rcp_datagram_set_payload(rcp_datagram_t* dgram, const void* data, size_t length) {
    if (!dgram || length > RCP_MAX_PAYLOAD) {
        return -1;
    }

    if (data && length > 0) {
        // Copy new payload
        memcpy(dgram->payload, data, length);
        dgram->header.payload_len = length;
    } else {
        // Clear payload
        memset(dgram->payload, 0, RCP_MAX_PAYLOAD);
        dgram->header.payload_len = 0;
    }

    return 0;
}

/* Compute and set the checksum for this datagram (header + payload) */
static inline void rcp_datagram_compute_checksum(rcp_datagram_t* dgram) {
    if (!dgram) {
        return;
    }

    // Compute checksum over header and payload
    rcp_compute_checksum(&dgram->header, dgram->payload, dgram->header.payload_len);
}

/* Verify the checksum of an RCP datagram
 * Returns 1 if valid, 0 if invalid, -1 on error */
static inline int rcp_datagram_verify_checksum(const rcp_datagram_t* dgram) {
    if (!dgram) {
        return -1;
    }

    // Verify checksum of both header and payload
    return rcp_verify_checksum(&dgram->header, dgram->payload, dgram->header.payload_len);
}