#pragma once

#include "bytestream.h"
#include "nrf.h"
#include "queue-ext-T.h"
#include "router.h"
#include "types.h"

/********* TYPES *********/

/* Initial window size and timeout constants */
#define INITIAL_WINDOW_SIZE 1024
#define S_TO_US(s) ((s) * 1000000)
#define RTO_INITIAL_US S_TO_US(1)

/* Segments that have been sent but not yet acknowledged */
typedef struct unacked_segment {
    struct unacked_segment *next; /* Used for queue - next segment in the queue */
    sender_segment_t seg;         /* The actual segment that was sent */
} unacked_segment_t;

/* Retransmission queue */
typedef struct rtq {
    unacked_segment_t *head, *tail;
} rtq_t;

/* Generate queue functions for the retransmission queue */
gen_queue_T(rtq, rtq_t, head, tail, unacked_segment_t, next);

/* Sender state structure */
typedef struct sender {
    nrf_t *nrf;          /* NRF interface for sending segments */
    bytestream_t reader; /* App writes data to it, sender reads from it */

    uint8_t local_addr;  /* Local RCP address */
    uint8_t remote_addr; /* Remote RCP address */

    uint16_t next_seqno;  /* Next sequence number to send */
    uint16_t acked_seqno; /* Sequence number of the highest acked segment */
    uint16_t window_size; /* Receiver's advertised window size */

    rtq_t pending_segs;      /* Queue of segments that have been sent but not yet acked */
    uint32_t initial_RTO_us; /* Initial RTO (in microseconds) */
    uint32_t rto_time_us;    /* Time when earliest outstanding segment will be retransmitted */
    uint32_t n_retransmits;  /* Number of times earliest outstanding segment has retransmitted */
} sender_t;

/********* HELPER FUNCTIONS *********/

/**
 * Convert a sender segment to an RCP datagram
 *
 * @param sender Pointer to the sender containing addressing information
 * @param segment Pointer to the sender segment to convert
 * @return An RCP datagram containing the converted data
 */
rcp_datagram_t sender_segment_to_rcp(sender_t *sender, sender_segment_t *segment) {
    assert(sender);
    assert(segment);

    rcp_datagram_t datagram = rcp_datagram_init();

    /* Set the source and destination addresses */
    datagram.header.src = sender->local_addr;
    datagram.header.dst = sender->remote_addr;

    /* Set the flags */
    if (segment->is_syn) {
        rcp_set_flag(&datagram.header, RCP_FLAG_SYN);
    }

    if (segment->is_fin) {
        rcp_set_flag(&datagram.header, RCP_FLAG_FIN);
    }

    /* Set the sequence number */
    datagram.header.seqno = segment->seqno;

    /* Set the payload (only if there is data to send) */
    if (segment->len > 0) {
        rcp_datagram_set_payload(&datagram, segment->payload, segment->len);
    }

    /* Zero out the unused fields (for the receiving message) */
    datagram.header.ackno = 0;
    datagram.header.window = 0;

    /* Compute the checksum over header and payload */
    rcp_datagram_compute_checksum(&datagram);

    return datagram;
}

/**
 * Convert a receiver segment (ACK) to an RCP datagram
 *
 * @param sender Pointer to the sender containing addressing information
 * @param segment Pointer to the receiver segment to convert
 * @return An RCP datagram containing the converted data
 */
rcp_datagram_t receiver_segment_to_rcp_from_sender(sender_t *sender, receiver_segment_t *segment) {
    assert(sender);
    assert(segment);

    rcp_datagram_t datagram = rcp_datagram_init();

    /* Set the source and destination addresses */
    datagram.header.src = sender->local_addr;
    datagram.header.dst = sender->remote_addr;

    /* Set the ACK flag */
    rcp_set_flag(&datagram.header, RCP_FLAG_ACK);

    /* Set the acknowledgment number */
    datagram.header.ackno = segment->ackno;

    /* Set the window size */
    datagram.header.window = segment->window_size;

    /* Zero out the unused fields */
    datagram.header.seqno = 0;
    datagram.header.payload_len = 0;

    /* Compute the checksum over header only (no payload) */
    rcp_datagram_compute_checksum(&datagram);

    return datagram;
}

/**
 * Convert a sender segment with ACK to an RCP datagram (for SYN-ACK)
 *
 * @param sender Pointer to the sender containing addressing information
 * @param segment Pointer to the sender segment to convert
 * @param ack Pointer to the acknowledgment information
 * @return An RCP datagram containing the converted data with ACK flag set
 */
rcp_datagram_t sender_segment_with_ack_to_rcp(sender_t *sender, sender_segment_t *segment,
                                              receiver_segment_t *ack) {
    assert(sender);
    assert(segment);
    assert(ack);

    /* First create a normal RCP datagram */
    rcp_datagram_t datagram = sender_segment_to_rcp(sender, segment);

    /* Then add ACK information */
    rcp_set_flag(&datagram.header, RCP_FLAG_ACK);
    datagram.header.ackno = ack->ackno;
    datagram.header.window = ack->window_size;

    /* Recompute the checksum with the added ACK information */
    rcp_datagram_compute_checksum(&datagram);

    return datagram;
}

/********* SENDER *********/

/**
 * Initialize the sender with default state
 *
 * @param nrf NRF interface for sending data
 * @param local_addr Local RCP address
 * @param remote_addr Remote RCP address
 * @return Initialized sender structure
 */
sender_t sender_init(nrf_t *nrf, uint8_t local_addr, uint8_t remote_addr) {
    sender_t sender = {
        .nrf = nrf,
        .reader = bs_init(),
        .next_seqno = 0,
        .acked_seqno = 0,
        .window_size = INITIAL_WINDOW_SIZE,
        .initial_RTO_us = RTO_INITIAL_US,
        .rto_time_us = 0,
        .n_retransmits = 0,
        .local_addr = local_addr,
        .remote_addr = remote_addr,
    };
    rtq_init(&sender.pending_segs);
    return sender;
}

/**
 * Create a segment to be sent
 *
 * @param sender The sender to create the segment for
 * @param len The maximum length of the data to send
 * @return The created segment
 */
sender_segment_t make_segment(sender_t *sender, size_t len) {
    assert(sender);

    sender_segment_t seg = {
        .len = 0,
        .seqno = sender->next_seqno,
        .is_syn = (sender->next_seqno == 0),
        .is_fin = false,
    };

    // Determine how many bytes to send (limit by max payload and requested length)
    size_t bytes_to_send = MIN(RCP_MAX_PAYLOAD, len);
    if (bytes_to_send > 0) {
        // Read data from bytestream into segment payload
        seg.len = bs_read(&sender->reader, seg.payload, bytes_to_send);
    }

    // Check if this is the FIN segment
    seg.is_fin = bs_reader_finished(&sender->reader);

    return seg;
}

/**
 * Callback function for transmitting segments
 *
 * @param sender The sender that will transmit the segment to its remote peer
 * @param segment The segment to transmit
 */
void transmit_segment(sender_t *sender, sender_segment_t *segment) {
    assert(sender);
    assert(segment);

    /* We always use the sender's NRF to send messages out */
    nrf_t *sender_nrf = sender->nrf;

    /* Get the next hop NRF address from the routing table */
    uint8_t src_rcp = sender->local_addr;
    uint8_t dst_rcp = sender->remote_addr;
    uint32_t next_hop_nrf = rtable_map[src_rcp][dst_rcp];

    /* Convert the sender_segment_t to a rcp_datagram_t */
    rcp_datagram_t datagram = sender_segment_to_rcp(sender, segment);

    /* Serialize the datagram */
    uint8_t buffer[RCP_TOTAL_SIZE];
    uint16_t length = rcp_datagram_serialize(&datagram, buffer, RCP_TOTAL_SIZE);

    /* Send the segment to the next hop NRF address */
    nrf_send_noack(sender_nrf, next_hop_nrf, buffer, length);
}

/**
 * Send a segment to the remote peer
 *
 * @param sender The sender to send the segment from
 * @param seg The segment to send
 * @return True if successful, false otherwise
 */
bool sender_send_segment(sender_t *sender, sender_segment_t seg) {
    assert(sender);

    printk("  [SEND] Sending segment %u to %u with length %u\n", seg.seqno, seg.seqno + seg.len,
           seg.len);

    // Send the segment to the remote peer
    transmit_segment(sender, &seg);

    // Only track segments with data, SYN, or FIN
    if (seg.len > 0 || seg.is_syn || seg.is_fin) {
        // Create a new unacked segment and copy the segment data
        unacked_segment_t *pending = kmalloc(sizeof(unacked_segment_t));
        if (!pending) {
            // Handle memory allocation failure
            return false;
        }

        // Copy the segment data
        memcpy(&pending->seg, &seg, sizeof(sender_segment_t));
        pending->next = NULL;

        // Set retransmission timer if this is the first segment in the queue
        if (rtq_empty(&sender->pending_segs)) {
            sender->rto_time_us = timer_get_usec() + sender->initial_RTO_us;
        }

        // Add the segment to the unacked queue
        rtq_push(&sender->pending_segs, pending);

        // Update next sequence number
        sender->next_seqno += seg.len;

        // SYN and FIN take up one sequence number each
        if (seg.is_syn || seg.is_fin) {
            sender->next_seqno++;
        }
    }

    return true;
}

/**
 * Send a segment with ACK to the remote peer (for SYN-ACK)
 *
 * @param sender The sender to send the segment from
 * @param seg The segment to send
 * @param ack The acknowledgment to include
 * @return True if successful, false otherwise
 */
bool sender_send_segment_with_ack(sender_t *sender, sender_segment_t *seg,
                                  receiver_segment_t *ack) {
    assert(sender);
    assert(seg);
    assert(ack);

    printk("  [SEND] Sending segment %u with ACK %u\n", seg->seqno, ack->ackno);

    /* We always use the sender's NRF to send messages out */
    nrf_t *sender_nrf = sender->nrf;

    /* Get the next hop NRF address from the routing table */
    uint8_t src_rcp = sender->local_addr;
    uint8_t dst_rcp = sender->remote_addr;
    uint32_t next_hop_nrf = rtable_map[src_rcp][dst_rcp];

    /* Convert the sender_segment_t and receiver_segment_t to a rcp_datagram_t */
    rcp_datagram_t datagram = sender_segment_with_ack_to_rcp(sender, seg, ack);

    /* Serialize the datagram */
    uint8_t buffer[RCP_TOTAL_SIZE];
    uint16_t length = rcp_datagram_serialize(&datagram, buffer, RCP_TOTAL_SIZE);

    /* Send the segment to the next hop NRF address */
    nrf_send_noack(sender_nrf, next_hop_nrf, buffer, length);

    // Only track segments with data, SYN, or FIN
    if (seg->len > 0 || seg->is_syn || seg->is_fin) {
        // Create a new unacked segment and copy the segment data
        unacked_segment_t *pending = kmalloc(sizeof(unacked_segment_t));
        if (!pending) {
            // Handle memory allocation failure
            return false;
        }

        // Copy the segment data
        memcpy(&pending->seg, seg, sizeof(sender_segment_t));
        pending->next = NULL;

        // Set retransmission timer if this is the first segment in the queue
        if (rtq_empty(&sender->pending_segs)) {
            sender->rto_time_us = timer_get_usec() + sender->initial_RTO_us;
        }

        // Add the segment to the unacked queue
        rtq_push(&sender->pending_segs, pending);

        // Update next sequence number
        sender->next_seqno += seg->len;

        // SYN and FIN take up one sequence number each
        if (seg->is_syn || seg->is_fin) {
            sender->next_seqno++;
        }
    }

    return true;
}

/**
 * Send a pure ACK segment (no data)
 *
 * @param sender The sender to send the ACK from
 * @param ack The acknowledgment to send
 * @return True if successful, false otherwise
 */
bool sender_send_ack(sender_t *sender, receiver_segment_t *ack) {
    assert(sender);
    assert(ack);

    printk("  [SEND %x] Sending pure ACK %u\n", sender->local_addr, ack->ackno);

    /* We always use the sender's NRF to send messages out */
    nrf_t *sender_nrf = sender->nrf;

    /* Get the next hop NRF address from the routing table */
    uint8_t src_rcp = sender->local_addr;
    uint8_t dst_rcp = sender->remote_addr;
    uint32_t next_hop_nrf = rtable_map[src_rcp][dst_rcp];

    /* Convert the receiver_segment_t to a rcp_datagram_t */
    rcp_datagram_t datagram = receiver_segment_to_rcp_from_sender(sender, ack);

    /* Serialize the datagram */
    uint8_t buffer[RCP_TOTAL_SIZE];
    uint16_t length = rcp_datagram_serialize(&datagram, buffer, RCP_TOTAL_SIZE);

    /* Send the ACK to the next hop NRF address */
    nrf_send_noack(sender_nrf, next_hop_nrf, buffer, length);

    return true;
}

/**
 * Push data from the bytestream to be sent to the remote peer
 *
 * @param sender The sender to push data from
 */
void sender_push(sender_t *sender) {
    assert(sender);

    // If FIN has been sent, no more data can be pushed
    if (bs_reader_finished(&sender->reader) &&
        (sender->next_seqno > bs_bytes_popped(&sender->reader) + 1)) {
        // The seqno of FIN is `1 + bytes_popped`, so if next_seqno is greater, we've sent FIN
        return;
    }

    // Edge case: if receiver window is 0 and no outstanding segments, send probe segment
    if (sender->window_size == 0) {
        if (rtq_empty(&sender->pending_segs)) {
            // Send a zero-length segment to probe for window update
            sender_segment_t seg = make_segment(sender, 0);
            sender_send_segment(sender, seg);
        }
        return;
    }

    // Check if receiver has enough space to receive more data
    uint32_t receiver_max_seqno = sender->acked_seqno + sender->window_size;
    if (receiver_max_seqno < sender->next_seqno) {
        // No space in receiver window
        return;
    }

    // Send data if available in the bytestream
    if (bs_bytes_available(&sender->reader)) {
        uint32_t remaining_space = receiver_max_seqno - sender->next_seqno;
        sender_segment_t seg = make_segment(sender, remaining_space);
        sender_send_segment(sender, seg);
    } else if (bs_reader_finished(&sender->reader) && !rtq_empty(&sender->pending_segs)) {
        // If bytestream is finished but we haven't sent FIN yet, send it
        unacked_segment_t *last_seg = rtq_start(&sender->pending_segs);
        bool fin_needed = true;

        // Check if the last segment in the queue is already a FIN
        while (last_seg) {
            if (last_seg->seg.is_fin) {
                fin_needed = false;
                break;
            }
            last_seg = last_seg->next;
        }

        if (fin_needed) {
            sender_segment_t fin_seg = {
                .seqno = sender->next_seqno, .is_syn = false, .is_fin = true, .len = 0};
            sender_send_segment(sender, fin_seg);
        }
    }
}

/**
 * Process a reply from the receiver
 *
 * @param sender The sender to process the reply for
 * @param reply The reply segment from the receiver
 */
void sender_process_reply(sender_t *sender, receiver_segment_t *reply) {
    assert(sender);
    assert(reply);

    if (reply->is_ack) {
        // Validate ACK number doesn't exceed what we've sent
        if (reply->ackno > sender->next_seqno) {
            return;
        }

        // Update highest acknowledged sequence number
        sender->acked_seqno = reply->ackno;

        // Process acknowledged segments
        bool new_data_acked = false;
        while (!rtq_empty(&sender->pending_segs)) {
            unacked_segment_t *seg = rtq_start(&sender->pending_segs);

            // Calculate the sequence number after this segment
            uint16_t seg_end_seqno = seg->seg.seqno + seg->seg.len;
            if (seg->seg.is_syn || seg->seg.is_fin) {
                seg_end_seqno++;
            }

            // If this segment is not fully acknowledged, stop
            if (reply->ackno < seg_end_seqno) {
                break;
            }

            // Remove fully acknowledged segment from queue
            rtq_pop(&sender->pending_segs);
            new_data_acked = true;
        }

        // Reset retransmission timer if new data was acknowledged
        if (new_data_acked) {
            if (!rtq_empty(&sender->pending_segs)) {
                sender->rto_time_us = timer_get_usec() + sender->initial_RTO_us;
            }
            sender->n_retransmits = 0;
        }
    }

    // Update window size from receiver
    sender->window_size = reply->window_size;
}

/**
 * Check if any segments need to be retransmitted
 *
 * @param sender The sender to check for retransmits
 */
void sender_check_retransmits(sender_t *sender) {
    assert(sender);

    // Only check if there are pending segments and the timer has expired
    uint32_t now_us = timer_get_usec();
    int32_t time_since_rto = now_us - sender->rto_time_us;
    if (time_since_rto >= 0 && !rtq_empty(&sender->pending_segs)) {
        // Retransmit the oldest unacknowledged segment
        unacked_segment_t *seg = rtq_start(&sender->pending_segs);
        printk(" [RETRANS]  Sending segment %u to %u with length %u\n", seg->seg.seqno,
               seg->seg.seqno + seg->seg.len, seg->seg.len);
        transmit_segment(sender, &seg->seg);

        // Update retransmission timer - use exponential backoff if window is nonzero
        if (sender->window_size) {
            // Exponential backoff: double RTO for each retransmission
            sender->rto_time_us = now_us + (sender->initial_RTO_us * (1 << sender->n_retransmits));
            sender->n_retransmits++;
        } else {
            // If window is zero, use fixed RTO for persistent probing
            sender->rto_time_us = now_us + sender->initial_RTO_us;
        }
    }
}