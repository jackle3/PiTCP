#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Include types first so nrf_t is defined
#include "nrf.h"
#include "types.h"

// Now define our mock function (after nrf_t is defined)
static int mock_nrf_send_noack(nrf_t *nic, uint32_t txaddr, const void *msg, unsigned nbytes);

// Here's the key part: UNDEFINE the original function first, then redefine it
#undef nrf_send_noack
#define nrf_send_noack mock_nrf_send_noack

// Now include the rest of the headers
#include "bytestream.h"
#include "rcp-datagram.h"
#include "receiver.h"
#include "sender.h"
#include "tcp.h"

// Track the last segments transmitted
static sender_segment_t last_sender_segment;
static receiver_segment_t last_ack;
static int ack_count = 0;
static int sender_segment_count = 0;

// Mock NRF for testing
typedef struct mock_nrf {
    int dummy;
} mock_nrf_t;

mock_nrf_t *mock_nrf_init(void) {
    mock_nrf_t *nrf = kmalloc(sizeof(mock_nrf_t));
    memset(nrf, 0, sizeof(mock_nrf_t));
    return nrf;
}

// Implementation of our mock function to intercept sent data
static int mock_nrf_send_noack(nrf_t *nic, uint32_t txaddr, const void *msg, unsigned nbytes) {
    printk("Mock nrf_send_noack: addr=%u, nbytes=%u\n", txaddr, nbytes);

    // If this is a datagram, try to capture info about what was sent
    if (nbytes >= RCP_HEADER_LENGTH) {
        rcp_datagram_t datagram = rcp_datagram_init();
        if (rcp_datagram_parse(&datagram, msg, nbytes) > 0) {
            // Check if it's an ACK message
            if (rcp_has_flag(&datagram.header, RCP_FLAG_ACK)) {
                // Convert to receiver segment (ACK)
                receiver_segment_t seg = rcp_to_receiver_segment(&datagram);
                memcpy(&last_ack, &seg, sizeof(receiver_segment_t));
                ack_count++;
                printk("<transmit> Receiver ACK: ackno=%u, window_size=%u\n", seg.ackno,
                       seg.window_size);
            } else {
                // It's a data segment from sender
                sender_segment_t seg = rcp_to_sender_segment(&datagram);
                memcpy(&last_sender_segment, &seg, sizeof(sender_segment_t));
                sender_segment_count++;
                printk(
                    "<transmit> Sender transmit: seqno=%u, len=%u, expected_ackno=%u, is_syn=%d, "
                    "is_fin=%d\n",
                    seg.seqno, seg.len, seg.seqno + seg.len, seg.is_syn, seg.is_fin);

                if (seg.len > 0) {
                    // Copy payload into printed message - handle non-null terminated data
                    char payload_str[RCP_MAX_PAYLOAD + 1];
                    memcpy(payload_str, seg.payload, seg.len);
                    payload_str[seg.len] = '\0';
                    printk("Payload: %s\n", payload_str);
                }
            }
        }
    }

    return nbytes;
}

// Helper function to send a segment and process it on the receiver side
static void send_and_process(sender_t *sender, receiver_t *receiver) {
    // Reset segment count to track if a new segment is sent
    sender_segment_count = 0;
    ack_count = 0;

    printk("Sender window: next_seqno=%u, acked_seqno=%u, window_size=%u\n", sender->next_seqno,
           sender->acked_seqno, sender->window_size);
    printk("Receiver window: bytes_written=%u, remaining_capacity=%u\n",
           bs_bytes_written(&receiver->writer), bs_remaining_capacity(&receiver->writer));

    // Trigger sender to create a segment
    sender_push(sender);

    // Check if a segment was actually created and transmitted
    if (sender_segment_count == 0) {
        printk("No segment was sent\n");
        return;
    }

    // Process the segment on the receiver side
    recv_process_segment(receiver, &last_sender_segment);

    // Check if an ACK was generated
    if (ack_count > 0) {
        // Process any ACK from receiver back to sender
        sender_process_reply(sender, &last_ack);
    }
}

// Test receiver functionality
static void test_receiver(void) {
    printk("--------------------------------\n");
    printk("Starting receiver test...\n");

    // Define local and remote addresses
    const uint8_t LOCAL_ADDR = 1;
    const uint8_t REMOTE_ADDR = 2;

    // Initialize mock NRF
    mock_nrf_t *mock_nrf = mock_nrf_init();
    assert(mock_nrf != NULL);

    // Initialize sender and receiver with the updated function signature
    sender_t sender = sender_init((nrf_t *)mock_nrf, LOCAL_ADDR, REMOTE_ADDR);
    receiver_t receiver = receiver_init((nrf_t *)mock_nrf, LOCAL_ADDR, REMOTE_ADDR);

    printk("Sender and receiver initialized\n");

    // Reset tracking variables
    ack_count = 0;
    memset(&last_ack, 0, sizeof(last_ack));

    // Test 1: Send SYN packet
    printk("\n----- Test 1: SYN packet -----\n");

    // Create and send a SYN segment manually
    sender_segment_t syn_segment = {.seqno = 0, .len = 0, .is_syn = true, .is_fin = false};

    // Process SYN segment directly
    recv_process_segment(&receiver, &syn_segment);

    // Verify SYN was processed correctly
    assert(receiver.syn_received);
    assert(ack_count > 0);
    assert(last_ack.ackno == 1);  // ACK for SYN should be 1
    printk("SYN processed correctly, received ACK with ackno=%u\n", last_ack.ackno);

    // Test 2: Send a single data segment
    printk("\n----- Test 2: Single data segment -----\n");

    // Reset state
    ack_count = 0;
    sender_segment_count = 0;

    // Write data to sender's bytestream
    const char *test_data = "Hello, TCP!";
    size_t len = strlen(test_data);
    size_t written = bs_write(&sender.reader, (uint8_t *)test_data, len);
    assert(written == len);
    printk("Wrote %u bytes to sender's bytestream: '%s'\n", written, test_data);

    // Send data from sender to receiver
    send_and_process(&sender, &receiver);

    // Verify data segment was processed correctly
    assert(ack_count > 0);
    assert(last_ack.ackno == 1 + len);  // ACK for SYN (1) + data

    // Check if data was correctly written to receiver's bytestream
    uint8_t read_buffer[100];
    size_t bytes_available = bs_bytes_available(&receiver.writer);
    assert(bytes_available == len);

    size_t read = bs_read(&receiver.writer, read_buffer, sizeof(read_buffer));
    assert(read == len);
    read_buffer[read] = '\0';

    assert(memcmp(read_buffer, test_data, len) == 0);
    printk("Data segment processed correctly: received '%s'\n", read_buffer);

    // Test 3: Send multiple segments
    printk("\n----- Test 3: Multiple data segments -----\n");

    // Reset state
    ack_count = 0;

    // Write longer data to sender's bytestream to trigger multiple segments
    const char *long_data =
        "This is a longer message that should be split into multiple segments when sent using the "
        "TCP-like protocol we've implemented.";
    size_t long_len = strlen(long_data);
    written = bs_write(&sender.reader, (uint8_t *)long_data, long_len);
    assert(written == long_len);
    printk("Wrote %u bytes to sender's bytestream for multi-segment test\n", written);

    // Send and process all data
    uint16_t prev_ackno = last_ack.ackno;

    // Send data until all bytes are sent
    while (bs_bytes_available(&sender.reader) > 0) {
        send_and_process(&sender, &receiver);
        printk("Sent segment, received ACK with ackno=%u\n", last_ack.ackno);
    }

    // Verify all data was processed
    assert(last_ack.ackno > prev_ackno);

    // Check if data was correctly written to receiver's bytestream
    bytes_available = bs_bytes_available(&receiver.writer);
    assert(bytes_available == long_len);

    uint8_t long_buffer[512];
    read = bs_read(&receiver.writer, long_buffer, sizeof(long_buffer));
    assert(read == long_len);
    long_buffer[read] = '\0';

    assert(memcmp(long_buffer, long_data, long_len) == 0);
    printk("Multiple segments processed correctly\n");

    // Test 4: Out-of-order segments
    printk("\n----- Test 4: Out-of-order segments -----\n");

    // Reset state
    ack_count = 0;
    sender_segment_count = 0;

    // Create three segments with out-of-order sequence numbers
    const char *seg1_data = "First segment";
    const char *seg3_data = "Third segment";
    const char *seg2_data = "Second segment";

    // Sequence numbers relative to current state
    uint16_t base_seqno = sender.next_seqno;

    // Create properly formatted segments
    sender_segment_t seg1 = {
        .seqno = base_seqno, .len = strlen(seg1_data), .is_syn = false, .is_fin = false};
    memcpy(seg1.payload, seg1_data, seg1.len);

    sender_segment_t seg2 = {.seqno = base_seqno + strlen(seg1_data),
                             .len = strlen(seg2_data),
                             .is_syn = false,
                             .is_fin = false};
    memcpy(seg2.payload, seg2_data, seg2.len);

    sender_segment_t seg3 = {.seqno = base_seqno + strlen(seg1_data) + strlen(seg2_data),
                             .len = strlen(seg3_data),
                             .is_syn = false,
                             .is_fin = false};
    memcpy(seg3.payload, seg3_data, seg3.len);

    // Send segments in out-of-order sequence: 1, 3, 2
    printk("Sending segment 1\n");
    sender_send_segment(&sender, seg1);
    recv_process_segment(&receiver, &seg1);
    if (ack_count > 0) {
        sender_process_reply(&sender, &last_ack);
    }

    printk("\nSending segment 3 (out of order)\n");
    sender_send_segment(&sender, seg3);
    recv_process_segment(&receiver, &seg3);
    if (ack_count > 0) {
        sender_process_reply(&sender, &last_ack);
    }

    printk("\nSending segment 2 (fills the gap)\n");
    sender_send_segment(&sender, seg2);
    recv_process_segment(&receiver, &seg2);
    if (ack_count > 0) {
        sender_process_reply(&sender, &last_ack);
    }

    // Check that all segments were reassembled correctly
    uint8_t reassembled[100];
    read = bs_read(&receiver.writer, reassembled, sizeof(reassembled));
    reassembled[read] = '\0';

    char expected[100];
    size_t offset = 0;
    memcpy(expected + offset, seg1_data, strlen(seg1_data));
    offset += strlen(seg1_data);
    memcpy(expected + offset, seg2_data, strlen(seg2_data));
    offset += strlen(seg2_data);
    memcpy(expected + offset, seg3_data, strlen(seg3_data));
    offset += strlen(seg3_data);
    expected[offset] = '\0';

    printk("reassembled: %s\n", reassembled);
    printk("expected: %s\n", expected);
    printk("sender.next_seqno: %d\n", sender.next_seqno);

    assert(memcmp(reassembled, expected, read) == 0);
    printk("Out-of-order segments reassembled correctly: '%s'\n", reassembled);

    // Test 5: FIN segment
    printk("\n----- Test 5: FIN segment -----\n");

    // Reset state
    ack_count = 0;

    // Write final data and end the input stream
    const char *final_data = "Final message before FIN";
    written = bs_write(&sender.reader, (uint8_t *)final_data, strlen(final_data));
    bs_end_input(&sender.reader);

    // Keep sending until FIN is sent
    bool fin_observed = false;
    while (!fin_observed) {
        // Push more data and try to send FIN
        sender_push(&sender);

        // Check if a segment was actually transmitted
        if (sender_segment_count > 0) {
            // Process the segment on the receiver side
            recv_process_segment(&receiver, &last_sender_segment);

            // Check if the last sent segment had the FIN flag
            if (last_sender_segment.is_fin) {
                fin_observed = true;
                printk("FIN flag observed\n");
            }

            // Process any ACK from receiver back to sender
            if (ack_count > 0) {
                sender_process_reply(&sender, &last_ack);
            }
        }

        // Exit if FIN was observed or no more data available including FIN sent
        if (fin_observed ||
            (bs_reader_finished(&sender.reader) && !bs_bytes_available(&sender.reader) &&
             sender.next_seqno > sender.acked_seqno)) {
            break;
        }
    }

    // Verify FIN was processed correctly
    assert(fin_observed);
    assert(bs_writer_finished(&receiver.writer));

    // Final ACK should include +1 for FIN
    uint16_t expected_ackno = 1 +         // SYN
                              len +       // First test
                              long_len +  // Multi-segment test
                              strlen(seg1_data) + strlen(seg2_data) +
                              strlen(seg3_data) +   // Out-of-order test
                              strlen(final_data) +  // Final data
                              1;                    // FIN

    assert(last_ack.ackno == expected_ackno);
    printk("FIN processed correctly, final ACK ackno=%u (expected %u)\n", last_ack.ackno,
           expected_ackno);

    printk("Receiver test passed!\n");
    printk("--------------------------------\n");
}

void notmain(void) {
    printk("Starting TCP implementation tests...\n\n");
    kmalloc_init(64);
    printk("Memory initialized\n");

    test_receiver();

    printk("\nReceiver test passed!\n");
}