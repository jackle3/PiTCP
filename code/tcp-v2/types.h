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