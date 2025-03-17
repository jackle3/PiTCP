#pragma once

#include "rpi.h"

/* Total size of RCP packet (header + max payload) */
#define RCP_TOTAL_SIZE 32
/* RCP header length in bytes (reduced by 1 due to combined src/dst) */
#define RCP_HEADER_LENGTH 9 /* Reduced by 1 due to combined flags/payload_len */
/* Maximum payload size to fit in 32-byte packet */
#define RCP_MAX_PAYLOAD (RCP_TOTAL_SIZE - RCP_HEADER_LENGTH)

/* Flag bits for the flags field (using upper 3 bits) */
#define RCP_FLAG_FIN (1 << 5) /* FIN flag */
#define RCP_FLAG_SYN (1 << 6) /* SYN flag */
#define RCP_FLAG_ACK (1 << 7) /* ACK flag */

/* Mask for payload length (lower 5 bits) */
#define RCP_PAYLOAD_LEN_MASK 0x1F /* 5 bits for payload length (0-31) */
#define RCP_FLAGS_MASK 0xE0       /* Upper 3 bits for flags */

/* Address masks for combined src/dst byte */
#define RCP_SRC_MASK 0xF0 /* Upper 4 bits for source */
#define RCP_DST_MASK 0x0F /* Lower 4 bits for destination */
#define RCP_SRC_SHIFT 4   /* Shift amount for source address */

// #define DEBUG

// Debug printing macros
#ifdef DEBUG
#define DEBUG_PRINT(fmt, args...) printk(fmt, ##args)
#else
#define DEBUG_PRINT(fmt, args...) /* nothing */
#endif

/*
 * RCP Header Format (9 bytes total):
 * Byte 0:     Checksum (1 byte)
 * Byte 1:     Combined Address (src in upper 4 bits, dst in lower 4 bits) (1 byte)
 * Bytes 2-3:  Sequence Number (2 bytes)
 * Byte 4:     Combined Flags and Payload Length (flags in upper 3 bits, length in lower 5 bits) (1
 * byte) Bytes 5-6:  Acknowledgment Number (2 bytes) Bytes 7-8:  Window Size (2 bytes)
 */
typedef struct rcp_header {
    uint8_t cksum;     /* Checksum covering header and payload */
    uint8_t addr;      /* Combined source and destination address */
    uint16_t seqno;    /* Sequence number */
    uint8_t flags_len; /* Combined flags (upper 3 bits) and payload length (lower 5 bits) */
    uint16_t ackno;    /* Acknowledgment number */
    uint16_t window;   /* Window size */
} __attribute__((packed)) rcp_header_t;

_Static_assert(sizeof(rcp_header_t) == RCP_HEADER_LENGTH, "RCP header size mismatch");

/* Forward declarations for inline functions */
static inline rcp_header_t rcp_header_init(void);
static inline uint8_t rcp_calculate_checksum(const rcp_header_t *hdr, const uint8_t *payload,
                                             size_t payload_len);
static inline void rcp_compute_checksum(rcp_header_t *hdr, const uint8_t *payload,
                                        size_t payload_len);
static inline int rcp_verify_checksum(const rcp_header_t *hdr, const uint8_t *payload,
                                      size_t payload_len);
static inline void rcp_header_parse(rcp_header_t *hdr, const void *data);
static inline void rcp_header_serialize(const rcp_header_t *hdr, void *data);

/* Helper functions for address manipulation */
static inline void rcp_set_src_addr(rcp_header_t *hdr, uint8_t src) {
    hdr->addr = (hdr->addr & RCP_DST_MASK) | ((src << RCP_SRC_SHIFT) & RCP_SRC_MASK);
}

static inline void rcp_set_dst_addr(rcp_header_t *hdr, uint8_t dst) {
    hdr->addr = (hdr->addr & RCP_SRC_MASK) | (dst & RCP_DST_MASK);
}

static inline uint8_t rcp_get_src_addr(const rcp_header_t *hdr) {
    return (hdr->addr & RCP_SRC_MASK) >> RCP_SRC_SHIFT;
}

static inline uint8_t rcp_get_dst_addr(const rcp_header_t *hdr) { return hdr->addr & RCP_DST_MASK; }

/* Helper functions for flag and payload length manipulation */
static inline void rcp_set_flag(rcp_header_t *hdr, uint8_t flag) { hdr->flags_len |= flag; }

static inline void rcp_clear_flag(rcp_header_t *hdr, uint8_t flag) { hdr->flags_len &= ~flag; }

static inline int rcp_has_flag(const rcp_header_t *hdr, uint8_t flag) {
    return (hdr->flags_len & flag) != 0;
}

static inline void rcp_set_payload_len(rcp_header_t *hdr, uint8_t len) {
    // Clear the length bits and set the new length (ensuring it fits in 5 bits)
    hdr->flags_len = (hdr->flags_len & RCP_FLAGS_MASK) | (len & RCP_PAYLOAD_LEN_MASK);
}

static inline uint8_t rcp_get_payload_len(const rcp_header_t *hdr) {
    return hdr->flags_len & RCP_PAYLOAD_LEN_MASK;
}

/* Initialize RCP header with default values */
static inline rcp_header_t rcp_header_init(void) {
    rcp_header_t hdr = {.cksum = 0, .addr = 0, .seqno = 0, .flags_len = 0, .ackno = 0, .window = 0};
    return hdr;
}

/*
 * 16-bit one's complement sum checksum calculation
 * Similar to TCP/IP checksum but simplified for RCP
 */
static inline uint8_t rcp_calculate_checksum(const rcp_header_t *hdr, const uint8_t *payload,
                                             size_t payload_len) {
    if (!hdr) {
        return 0;
    }

    // Create a working copy of the header with checksum field zeroed
    rcp_header_t temp_hdr = *hdr;
    temp_hdr.cksum = 0;

    // Use 16-bit one's complement sum
    uint16_t sum = 0;
    const uint8_t *data = (const uint8_t *)&temp_hdr;

    // Sum header bytes as 16-bit words
    for (size_t i = 0; i < RCP_HEADER_LENGTH; i += 2) {
        if (i + 1 < RCP_HEADER_LENGTH) {
            sum += (data[i] << 8) | data[i + 1];
        } else {
            // Handle odd byte count
            sum += (data[i] << 8);
        }

        // Add carry
        while (sum >> 16) {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }
    }

    // Add payload bytes if present
    if (payload && payload_len > 0) {
        for (size_t i = 0; i < payload_len; i += 2) {
            if (i + 1 < payload_len) {
                sum += (payload[i] << 8) | payload[i + 1];
            } else {
                // Handle odd byte count
                sum += (payload[i] << 8);
            }

            // Add carry
            while (sum >> 16) {
                sum = (sum & 0xFFFF) + (sum >> 16);
            }
        }
    }

    // Take one's complement
    sum = ~sum;

    // Return 8-bit checksum (fold the 16-bit value)
    return (uint8_t)((sum & 0xFF) + ((sum >> 8) & 0xFF));
}

/*
 * Compute and set the header checksum in the header struct
 * This will calculate checksum over header and payload (if provided)
 */
static inline void rcp_compute_checksum(rcp_header_t *hdr, const uint8_t *payload,
                                        size_t payload_len) {
    if (!hdr) {
        return;
    }

    // Calculate checksum with the checksum field zeroed
    hdr->cksum = 0;
    hdr->cksum = rcp_calculate_checksum(hdr, payload, payload_len);
}

/*
 * Verify the checksum of header and payload
 * Returns 1 if valid, 0 if invalid
 */
static inline int rcp_verify_checksum(const rcp_header_t *hdr, const uint8_t *payload,
                                      size_t payload_len) {
    if (!hdr) {
        return 0;
    }

    // Save original checksum
    uint8_t original_cksum = hdr->cksum;

    // Create a copy of the header
    rcp_header_t temp_hdr = *hdr;
    temp_hdr.cksum = 0;

    // Calculate checksum with zeroed checksum field
    uint8_t calculated_cksum = rcp_calculate_checksum(&temp_hdr, payload, payload_len);

    // If checksum is valid, they should match
    return (calculated_cksum == original_cksum) ? 1 : 0;
}

/* Parse raw network data into an RCP header structure */
static inline void rcp_header_parse(rcp_header_t *hdr, const void *data) {
    if (!hdr || !data) {
        return;
    }

    const uint8_t *bytes = (const uint8_t *)data;

    DEBUG_PRINT("    [RCP] unparsed header bytes: ");
    for (size_t i = 0; i < RCP_HEADER_LENGTH; i++) {
        DEBUG_PRINT("%x ", bytes[i]);
    }
    DEBUG_PRINT("\n");

    hdr->cksum = bytes[0];
    hdr->addr = bytes[1];
    hdr->seqno = (bytes[2] << 8) | bytes[3];
    hdr->flags_len = bytes[4];
    hdr->ackno = (bytes[5] << 8) | bytes[6];
    hdr->window = (bytes[7] << 8) | bytes[8];

    DEBUG_PRINT("    [RCP] parsed header\n");
    DEBUG_PRINT("      - src: %u\n", rcp_get_src_addr(hdr));
    DEBUG_PRINT("      - dst: %u\n", rcp_get_dst_addr(hdr));
    DEBUG_PRINT("      - seqno: %u\n", hdr->seqno);
    DEBUG_PRINT("      - ackno: %u\n", hdr->ackno);
    DEBUG_PRINT("      - syn: %u\n", rcp_has_flag(hdr, RCP_FLAG_SYN));
    DEBUG_PRINT("      - ack: %u\n", rcp_has_flag(hdr, RCP_FLAG_ACK));
    DEBUG_PRINT("      - fin: %u\n", rcp_has_flag(hdr, RCP_FLAG_FIN));
    DEBUG_PRINT("      - payload_len: %u\n", rcp_get_payload_len(hdr));
}

/* Serialize an RCP header structure into network data */
static inline void rcp_header_serialize(const rcp_header_t *hdr, void *data) {
    if (!hdr || !data) {
        return;
    }

    DEBUG_PRINT("    [RCP] serializing header\n");
    DEBUG_PRINT("      - src: %u\n", rcp_get_src_addr(hdr));
    DEBUG_PRINT("      - dst: %u\n", rcp_get_dst_addr(hdr));
    DEBUG_PRINT("      - seqno: %u\n", hdr->seqno);
    DEBUG_PRINT("      - ackno: %u\n", hdr->ackno);
    DEBUG_PRINT("      - syn: %u\n", rcp_has_flag(hdr, RCP_FLAG_SYN));
    DEBUG_PRINT("      - ack: %u\n", rcp_has_flag(hdr, RCP_FLAG_ACK));
    DEBUG_PRINT("      - fin: %u\n", rcp_has_flag(hdr, RCP_FLAG_FIN));
    DEBUG_PRINT("      - payload_len: %u\n", rcp_get_payload_len(hdr));

    uint8_t *bytes = (uint8_t *)data;

    bytes[0] = hdr->cksum;
    bytes[1] = hdr->addr;
    bytes[2] = (hdr->seqno >> 8) & 0xFF;
    bytes[3] = hdr->seqno & 0xFF;
    bytes[4] = hdr->flags_len;
    bytes[5] = (hdr->ackno >> 8) & 0xFF;
    bytes[6] = hdr->ackno & 0xFF;
    bytes[7] = (hdr->window >> 8) & 0xFF;
    bytes[8] = hdr->window & 0xFF;

    DEBUG_PRINT("    [RCP] serialized header bytes: ");
    for (size_t i = 0; i < RCP_HEADER_LENGTH; i++) {
        DEBUG_PRINT("%x ", bytes[i]);
    }
    DEBUG_PRINT("\n");
}