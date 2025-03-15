#pragma once

#include "receiver.h"
#include "sender.h"

/********* TYPES *********/

/* TCP peer structure representing a connection endpoint */
typedef struct tcp_peer {
    sender_t sender;     /* Sender component of the connection */
    receiver_t receiver; /* Receiver component of the connection */

    uint32_t time_of_last_receipt;    /* Time when last packet was received */
    bool linger_after_streams_finish; /* Whether to linger after streams finish */
} tcp_peer_t;

/********* HELPER FUNCTIONS *********/

/**
 * Convert an RCP datagram to a sender segment
 *
 * @param datagram Pointer to the RCP datagram to convert
 * @return A sender segment structure containing the converted data
 */
sender_segment_t rcp_to_sender_segment(rcp_datagram_t *datagram) {
    assert(datagram);

    sender_segment_t seg = {
        .seqno = datagram->header.seqno,
        .is_syn = rcp_has_flag(&datagram->header, RCP_FLAG_SYN),
        .is_fin = rcp_has_flag(&datagram->header, RCP_FLAG_FIN),
        .len = datagram->header.payload_len,
    };

    /* Copy payload if present */
    if (datagram->payload && datagram->header.payload_len > 0) {
        memcpy(seg.payload, datagram->payload, seg.len);
    }

    return seg;
}

/**
 * Convert an RCP datagram to a receiver segment
 *
 * @param datagram Pointer to the RCP datagram to convert
 * @return A receiver segment structure containing the converted data
 */
receiver_segment_t rcp_to_receiver_segment(rcp_datagram_t *datagram) {
    assert(datagram);

    receiver_segment_t seg = {
        .ackno = datagram->header.ackno,
        .is_ack = rcp_has_flag(&datagram->header, RCP_FLAG_ACK),
        .window_size = datagram->header.window,
    };

    return seg;
}

/********* TCP PEER *********/

/**
 * Initialize a new TCP peer
 *
 * @param sender_nrf The NRF interface to use for sending segments
 * @param receiver_nrf The NRF interface to use for receiving segments
 * @param local_addr The local RCP address
 * @param remote_addr The remote RCP address
 * @return Initialized TCP peer structure
 */
static inline tcp_peer_t tcp_peer_init(nrf_t *sender_nrf, nrf_t *receiver_nrf, uint8_t local_addr,
                                       uint8_t remote_addr) {
    tcp_peer_t peer;

    peer.sender = sender_init(sender_nrf, local_addr, remote_addr);
    peer.receiver = receiver_init(receiver_nrf, local_addr, remote_addr);

    peer.time_of_last_receipt = timer_get_usec(); /* Initialize to current time */
    peer.linger_after_streams_finish = true;

    return peer;
}

/**
 * Check for and process any incoming segments from the remote
 *
 * @param peer The TCP peer to process
 */
static inline void tcp_check_incoming(tcp_peer_t *peer) {
    assert(peer);

    uint8_t buffer[RCP_TOTAL_SIZE];

    /* Try to receive a packet from NRF with a 1 ms timeout */
    int ret = nrf_read_exact_timeout(peer->receiver.nrf, buffer, RCP_TOTAL_SIZE, 1000);
    if (ret <= 0) {
        return; /* No data or error */
    }

    /* Try to parse the read packet into an RCP datagram */
    rcp_datagram_t datagram = rcp_datagram_init();
    if (rcp_datagram_parse(&datagram, buffer, ret) <= 0) {
        return; /* Parsing failed */
    }

    /* Verify the checksum of the received packet */
    if (!rcp_datagram_verify_checksum(&datagram)) {
        return; /* Invalid checksum */
    }

    /* Update time of last packet receipt */
    peer->time_of_last_receipt = timer_get_usec();

    /* Process based on segment type (ACK or data) */
    if (rcp_has_flag(&datagram.header, RCP_FLAG_ACK)) {
        /* Convert the RCP datagram to a receiver_segment_t */
        receiver_segment_t segment = rcp_to_receiver_segment(&datagram);

        /* Process the reply (might be ACK or window update) */
        sender_process_reply(&peer->sender, &segment);
    } else {
        /* Convert the RCP datagram to a sender_segment_t */
        sender_segment_t segment = rcp_to_sender_segment(&datagram);

        /* Process the segment (and potentially reply with an ACK) */
        recv_process_segment(&peer->receiver, &segment);
    }

    /* Free the payload if allocated */
    if (datagram.payload) {
        free(datagram.payload);
        datagram.payload = NULL;
    }
}

/**
 * Send any data that's pending in the sender's buffer to the remote
 *
 * @param peer The TCP peer to process
 */
static inline void tcp_send_pending(tcp_peer_t *peer) {
    assert(peer);

    /* Try to push any pending data from the bytestream to the network
       If we've reached the end of the input stream but haven't sent FIN yet,
       also try to push a FIN segment */
    if (bs_bytes_available(&peer->sender.reader) || bs_reader_finished(&peer->sender.reader)) {
        sender_push(&peer->sender);
    }
}

/**
 * Check for timeouts and handle retransmissions
 *
 * @param peer The TCP peer to process
 */
static inline void tcp_check_timeouts(tcp_peer_t *peer) {
    assert(peer);

    /* Check if any segments need to be retransmitted */
    sender_check_retransmits(&peer->sender);
}

/**
 * Main polling function that should be called regularly in your main loop
 *
 * @param peer The TCP peer to process
 */
static inline void tcp_tick(tcp_peer_t *peer) {
    assert(peer);

    tcp_check_incoming(peer);
    tcp_send_pending(peer);
    tcp_check_timeouts(peer);
}

/**
 * Write data to the TCP connection for sending
 *
 * @param peer The TCP peer to write to
 * @param data The data to write
 * @param len The length of the data
 * @return The number of bytes written
 */
static inline size_t tcp_write(tcp_peer_t *peer, const uint8_t *data, size_t len) {
    assert(peer);
    assert(data || len == 0);

    /* Write to the bytestream that the sender reads from */
    return bs_write(&peer->sender.reader, data, len);
}

/**
 * Read data from the TCP connection
 *
 * @param peer The TCP peer to read from
 * @param data The buffer to read into
 * @param len The maximum number of bytes to read
 * @return The number of bytes read
 */
static inline size_t tcp_read(tcp_peer_t *peer, uint8_t *data, size_t len) {
    assert(peer);
    assert(data || len == 0);

    /* Read from the bytestream that the receiver writes to */
    return bs_read(&peer->receiver.writer, data, len);
}

/**
 * Check if the TCP connection has data available to read
 *
 * @param peer The TCP peer to check
 * @return True if there is data available, false otherwise
 */
static inline bool tcp_has_data(tcp_peer_t *peer) {
    assert(peer);

    /* Check if the receiver's bytestream has data available to read */
    return bs_bytes_available(&peer->receiver.writer) > 0;
}

/**
 * App can call this to close the TCP connection
 * - This will close the sender bytestream and attempt to send a FIN
 * - Note that the receiver may still have data to write to the app, so the connection
 *   is not fully closed yet.
 * - The receiver will close its writing bytestream when it has received the FIN from
 *   the remote and has assembled all the data up to that point (regardless of whether
 *   the app has read it all yet).
 * - The connection remains in a lingering state for some time after both streams are
 *   closed to handle any delayed packets.
 *
 * @param peer The TCP peer to close
 */
static inline void tcp_close(tcp_peer_t *peer) {
    assert(peer);

    /* Mark the sender's bytestream as finished */
    bs_end_input(&peer->sender.reader);
    /* The next call to tcp_tick will attempt to send a FIN */
}

/**
 * Check if the TCP connection is active
 *
 * @param peer The TCP peer to check
 * @return True if the connection is still active
 */
static inline bool tcp_is_active(tcp_peer_t *peer) {
    assert(peer);

    uint32_t now = timer_get_usec();

    /* Sender is active if it has pending segments or is still reading from the app */
    bool sender_active =
        !rtq_empty(&peer->sender.pending_segs) || !bs_reader_finished(&peer->sender.reader);

    /* Receiver is active if it is still writing to the app */
    bool receiver_active = !bs_writer_finished(&peer->receiver.writer);

    /* We should linger for 10 RTOs (10 seconds) after the last packet was received
       - Mainly used when both sender and receiver is closed, and we want to ensure our
         ACK of the other side's FIN/ACK is received */
    bool lingering = peer->linger_after_streams_finish &&
                     (now < peer->time_of_last_receipt + 10 * peer->sender.initial_RTO_us);

    return (sender_active || receiver_active || lingering);
}

/**
 * Check if the receiving side of the connection is closed
 *
 * @param peer The TCP peer to check
 * @return True if the receiving side is closed
 */
static inline bool tcp_receive_closed(tcp_peer_t *peer) {
    assert(peer);

    /* Check if the receiver's bytestream is finished */
    return bs_writer_finished(&peer->receiver.writer);
}