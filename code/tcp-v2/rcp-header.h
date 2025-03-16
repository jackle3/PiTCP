#pragma once

#include "rpi.h"

#define RCP_HEADER_LENGTH 10 /* RCP header length in bytes */
#define RCP_MAX_PAYLOAD 21   /* Maximum payload size to fit in 32-byte packet */
#define RCP_TOTAL_SIZE 32    /* Total size of RCP packet (header + max payload) */

/* Flag bits for the flags field */
#define RCP_FLAG_FIN (1 << 0) /* FIN flag */
#define RCP_FLAG_SYN (1 << 1) /* SYN flag */
#define RCP_FLAG_ACK (1 << 2) /* ACK flag */

/*
 * RCP Header Format (10 bytes total):
 * Byte 0:     Checksum (1 byte)
 * Byte 1:     Destination Address (1 byte)
 * Byte 2:     Source Address (1 byte)
 * Bytes 3-4:  Sequence Number (2 bytes)
 * Byte 5:     Flags (FIN, SYN, ACK) (1 byte)
 * Bytes 6-7:  Acknowledgment Number (2 bytes)
 * Bytes 8-9:  Window Size (2 bytes)
 */
typedef struct rcp_header {
    uint8_t cksum;   /* Checksum covering header and payload */
    uint8_t dst;     /* Destination address */
    uint8_t src;     /* Source address */
    uint16_t seqno;  /* Sequence number */
    uint8_t flags;   /* Control flags (FIN, SYN, ACK) */
    uint16_t ackno;  /* Acknowledgment number */
    uint16_t window; /* Window size */
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

/* Helper functions for flag manipulation */
static inline void rcp_set_flag(rcp_header_t *hdr, uint8_t flag) { hdr->flags |= flag; }

static inline void rcp_clear_flag(rcp_header_t *hdr, uint8_t flag) { hdr->flags &= ~flag; }

static inline int rcp_has_flag(const rcp_header_t *hdr, uint8_t flag) {
    return (hdr->flags & flag) != 0;
}

/* Initialize RCP header with default values */
static inline rcp_header_t rcp_header_init(void) {
    rcp_header_t hdr = {
        .cksum = 0, .dst = 0, .src = 0, .seqno = 0, .flags = 0, .ackno = 0, .window = 0};
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

    printk("    [RCP] unparsed header bytes: ");
    for (size_t i = 0; i < RCP_HEADER_LENGTH; i++) {
        printk("%x ", bytes[i]);
    }
    printk("\n");

    hdr->cksum = bytes[0];
    hdr->dst = bytes[1];
    hdr->src = bytes[2];
    hdr->seqno = (bytes[3] << 8) | bytes[4];
    hdr->flags = bytes[5];
    hdr->ackno = (bytes[6] << 8) | bytes[7];
    hdr->window = (bytes[8] << 8) | bytes[9];

    // printk("    [RCP] parsed header\n");
    // printk("      - src: %u\n", hdr->src);
    // printk("      - dst: %u\n", hdr->dst);
    // printk("      - seqno: %u\n", hdr->seqno);
    // printk("      - ackno: %u\n", hdr->ackno);
    // printk("      - syn: %u\n", rcp_has_flag(hdr, RCP_FLAG_SYN));
    // printk("      - ack: %u\n", rcp_has_flag(hdr, RCP_FLAG_ACK));
    // printk("      - fin: %u\n", rcp_has_flag(hdr, RCP_FLAG_FIN));
    // printk("      - payload_len: %u\n", hdr->payload_len);
}

/* Serialize an RCP header structure into network data */
static inline void rcp_header_serialize(const rcp_header_t *hdr, void *data) {
    if (!hdr || !data) {
        return;
    }

    // printk("    [RCP] serializing header\n");
    // printk("      - src: %u\n", hdr->src);
    // printk("      - dst: %u\n", hdr->dst);
    // printk("      - seqno: %u\n", hdr->seqno);
    // printk("      - ackno: %u\n", hdr->ackno);
    // printk("      - syn: %u\n", rcp_has_flag(hdr, RCP_FLAG_SYN));
    // printk("      - ack: %u\n", rcp_has_flag(hdr, RCP_FLAG_ACK));
    // printk("      - fin: %u\n", rcp_has_flag(hdr, RCP_FLAG_FIN));
    // printk("      - payload_len: %u\n", hdr->payload_len);

    uint8_t *bytes = (uint8_t *)data;

    bytes[0] = hdr->cksum;
    bytes[1] = hdr->dst;
    bytes[2] = hdr->src;
    bytes[3] = (hdr->seqno >> 8) & 0xFF;
    bytes[4] = hdr->seqno & 0xFF;
    bytes[5] = hdr->flags;
    bytes[6] = (hdr->ackno >> 8) & 0xFF;
    bytes[7] = hdr->ackno & 0xFF;
    bytes[8] = (hdr->window >> 8) & 0xFF;
    bytes[9] = hdr->window & 0xFF;

    printk("    [RCP] serialized header bytes: ");
    for (size_t i = 0; i < RCP_HEADER_LENGTH; i++) {
        printk("%x ", bytes[i]);
    }
    printk("\n");
}