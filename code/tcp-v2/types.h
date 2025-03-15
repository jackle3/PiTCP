#pragma once

#include "rcp-datagram.h"
#include <stdbool.h>

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