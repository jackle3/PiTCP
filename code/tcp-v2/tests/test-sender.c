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
#include "sender.h"
#include "tcp.h"

// Track the last segment transmitted
static sender_segment_t last_segment;
static int segment_count = 0;

// Define our mock NRF structure
typedef struct mock_nrf {
    int dummy;
} mock_nrf_t;

mock_nrf_t *mock_nrf_init(void) {
    mock_nrf_t *nrf = kmalloc(sizeof(mock_nrf_t));
    memset(nrf, 0, sizeof(mock_nrf_t));
    return nrf;
}

// Implementation of our mock function
static int mock_nrf_send_noack(nrf_t *nic, uint32_t txaddr, const void *msg, unsigned nbytes) {
    printk("Mock nrf_send_noack: addr=%u, nbytes=%u\n", txaddr, nbytes);

    // If this is a datagram, try to capture info about what was sent
    if (nbytes >= RCP_HEADER_LENGTH) {
        rcp_datagram_t datagram = rcp_datagram_init();
        if (rcp_datagram_parse(&datagram, msg, nbytes) > 0) {
            // Check for SYN or FIN flags
            if (rcp_has_flag(&datagram.header, RCP_FLAG_FIN)) {
                printk("Detected FIN flag in outgoing packet\n");
                // Create a copy of the segment for later inspection
                sender_segment_t seg = rcp_to_sender_segment(&datagram);
                memcpy(&last_segment, &seg, sizeof(sender_segment_t));
                last_segment.is_fin = true;
                segment_count++;
            } else if (rcp_has_flag(&datagram.header, RCP_FLAG_SYN)) {
                printk("Detected SYN flag in outgoing packet\n");
                sender_segment_t seg = rcp_to_sender_segment(&datagram);
                memcpy(&last_segment, &seg, sizeof(sender_segment_t));
                last_segment.is_syn = true;
                segment_count++;
            } else if (datagram.header.payload_len > 0) {
                // Regular data packet
                sender_segment_t seg = rcp_to_sender_segment(&datagram);
                memcpy(&last_segment, &seg, sizeof(sender_segment_t));
                segment_count++;
            }
        }
    }

    return nbytes;
}

// Test sender functionality
static void test_sender(void) {
    printk("--------------------------------\n");
    printk("Starting sender test...\n");

    // Define local and remote addresses
    const uint8_t LOCAL_ADDR = 1;
    const uint8_t REMOTE_ADDR = 2;

    // Initialize mock NRF
    mock_nrf_t *mock_nrf = mock_nrf_init();
    assert(mock_nrf != NULL);

    // Initialize sender with the updated function signature
    sender_t sender = sender_init((nrf_t *)mock_nrf, LOCAL_ADDR, REMOTE_ADDR);
    printk("Sender initialized\n");

    // Write test data to the sender's bytestream
    const char *test_data = "This is a test message that will be split into multiple segments";
    size_t len = strlen(test_data);
    size_t written = bs_write(&sender.reader, (uint8_t *)test_data, len);
    assert(written == len);
    printk("Wrote %u bytes to sender's bytestream: '%s'\n", written, test_data);

    // Push data to be sent
    printk("--------------------------------\n");
    while (sender.next_seqno < len) {
        printk("Pushing data to send (should trigger segment creation)...\n");
        uint16_t remaining_space = sender.acked_seqno + sender.window_size - sender.next_seqno;
        while (remaining_space) {
            sender_push(&sender);
            remaining_space = sender.acked_seqno + sender.window_size - sender.next_seqno;
            printk("  Pushed data... next_seqno: %u, remaining_space: %u, bytes_popped: %u\n",
                   sender.next_seqno, remaining_space, bs_bytes_popped(&sender.reader));

            if (!bs_bytes_available(&sender.reader)) {
                printk("No more data to push\n");
                break;
            }
        }

        // Verify that data was pushed
        assert(sender.next_seqno > 0);
        assert(!rtq_empty(&sender.pending_segs));
        printk("Segments created and transmitted. Next seqno: %u, Window size: %u\n",
               sender.next_seqno, sender.window_size);

        printk("--------------------------------\n");
        // Create mock ACK from receiver
        receiver_segment_t reply = {0};
        reply.is_ack = true;
        reply.ackno = sender.next_seqno;  // ACK everything sent so far
        reply.window_size = 64;           // Increase window size

        // Process the ACK
        printk("Processing ACK with ackno=%u\n", reply.ackno);
        sender_process_reply(&sender, &reply);

        // Verify ACK was processed
        assert(sender.acked_seqno == reply.ackno);
        assert(sender.window_size == reply.window_size);
        assert(rtq_empty(&sender.pending_segs));  // All segments should be ACKed
        printk("ACK processed. Acked seqno: %u, Window size: %u\n", sender.acked_seqno,
               sender.window_size);
        printk("--------------------------------\n");
    }
    printk("--------------------------------\n");

    // Test retransmission mechanism
    printk("Testing retransmission mechanism...\n");

    // Write more data and push without ACKing
    const char *more_data = "More bytes for retransmission test";
    written = bs_write(&sender.reader, (uint8_t *)more_data, strlen(more_data));
    sender_push(&sender);
    printk("  Pushed data... next_seqno: %u, bytes_popped: %u\n", sender.next_seqno,
           bs_bytes_popped(&sender.reader));

    // Force retransmission time
    sender.rto_time_us = timer_get_usec() - S_TO_US(10);  // Set RTO time to past

    // Check retransmits
    printk("Checking for retransmits (should trigger retransmission)...\n");
    sender_check_retransmits(&sender);

    // Verify retransmission counter increased
    assert(sender.n_retransmits > 0);
    printk("Retransmission counter: %u\n", sender.n_retransmits);

    printk(
        "Checking that an RTO that doesn't trigger a retransmission doesn't trigger a "
        "retransmission...\n");
    sender.rto_time_us = timer_get_usec() + S_TO_US(10);  // Set RTO time to future
    sender.n_retransmits = 0;
    sender_check_retransmits(&sender);
    assert(sender.n_retransmits == 0);

    // Reset segment tracking before testing FIN behavior
    segment_count = 0;
    memset(&last_segment, 0, sizeof(last_segment));
    printk("--------------------------------\n");

    // End the stream
    printk("Ending input stream...\n");
    bs_end_input(&sender.reader);

    // Keep track of how many bytes were written to check if we've sent everything
    size_t total_bytes = bs_bytes_available(&sender.reader);

    printk("Pushing data until all bytes and FIN are sent...\n");
    printk("Total bytes to send: %u\n", total_bytes);

    // Keep pushing data until we observe the FIN
    bool fin_observed = false;

    // Keep track of the next_seqno to detect when a FIN is sent
    uint16_t prev_seqno = sender.next_seqno;

    while (!fin_observed) {
        sender_push(&sender);

        // Check our mock send function's captured data
        if (last_segment.is_fin) {
            fin_observed = true;
            printk("FIN flag observed on segment with seqno=%u\n", last_segment.seqno);
        }

        printk("  Pushed data... next_seqno: %u, bytes_available: %u, bytes_popped: %u\n",
               sender.next_seqno, bs_bytes_available(&sender.reader),
               bs_bytes_popped(&sender.reader));

        // If we've pushed all data and the sequence number increased without more data,
        // that might be the FIN. Let's check one more time.
        if (bs_reader_finished(&sender.reader) && !bs_bytes_available(&sender.reader) &&
            sender.next_seqno > prev_seqno && !fin_observed) {
            printk("Detected possible FIN (seqno increased without more data)\n");
            sender_push(&sender);  // One more push to make sure we send FIN

            if (last_segment.is_fin) {
                fin_observed = true;
                printk("FIN flag confirmed on segment with seqno=%u\n", last_segment.seqno);
            }
        }

        prev_seqno = sender.next_seqno;

        // Safety check to avoid infinite loop
        if (prev_seqno > len + strlen(more_data) + 10) {
            break;
        }
    }

    // Verify that we saw a FIN flag
    assert(fin_observed);
    printk("Verified FIN flag was set on the final segment\n");

    // Print final state
    printk("Final state - bs_eof: %d, bs_bytes_available: %u, bs_bytes_written: %u\n",
           sender.reader.eof, bs_bytes_available(&sender.reader), bs_bytes_written(&sender.reader));

    // Check for pending segments with FIN
    assert(!rtq_empty(&sender.pending_segs));
    printk("Stream ended. All data sent with FIN flag.\n");

    printk("Sender test passed!\n");
    printk("--------------------------------\n");
}

void notmain(void) {
    printk("Starting TCP implementation tests...\n\n");
    kmalloc_init(64);
    printk("Memory initialized\n");

    test_sender();

    printk("\nSender test passed!\n");
}