/**
 * TCP Peer-to-Peer File Sender
 *
 * This program runs on the initiator side (client) and sends a file to the server.
 * It establishes a TCP connection, transmits the file data, and verifies success.
 */

#include <string.h>

#include "libc/fast-hash32.h"
#include "nrf-test.h"
#include "tcp.h"

// RCP and NRF addresses
#define MY_RCP_ADDR 0x1
#define PEER_RCP_ADDR 0x2

// Test parameters
#define PROGRESS_INTERVAL 512  // How often to print progress (in ticks)
#define TICK_DELAY_MS 5         // Delay between ticks in milliseconds

// Select test data to send (uncomment one)
// #include "byte-array-hello.h"
// #include "byte-array-small-file.h"
// #include "byte-array-1mb-file.h"
// #include "byte-array-generated-5000.h"
#include "byte-array-generated-20000.h"

/**
 * Print file transfer progress
 */
static void print_transfer_progress(tcp_peer_t *peer, size_t bytes_written, size_t message_len,
                                    int iterations) {
    printk("\n[SENDER] Transfer progress (iterations: %d, written: %u/%u bytes):\n", iterations,
           bytes_written, message_len);

    // TCP status
    printk("[SENDER] TCP State: seqno=%u, acked=%u, window=%u, in_flight=%u\n",
           peer->sender.next_seqno, peer->sender.acked_seqno, peer->sender.window_size,
           peer->segs_in_flight);

    // Connection state
    bool sender_active =
        !bs_reader_finished(&peer->sender.reader) || !tcp_rtx_empty(&peer->rtx_queue);
    bool receiver_active = !bs_writer_finished(&peer->receiver.writer);
    bool lingering = peer->lingering &&
                     (timer_get_usec() - peer->time_of_last_receipt_us < TIME_WAIT_DURATION_US);

    printk("[SENDER] Connection state: sender_active=%d, receiver_active=%d, lingering=%d\n",
           sender_active, receiver_active, lingering);

    if (peer->segs_in_flight > 0) {
        printk("  First segment in flight: %u-%u",
               unwrap_seqno(peer->rtx_queue.head->segment.sender_segment.seqno,
                            peer->sender.next_seqno),
               unwrap_seqno(peer->rtx_queue.head->segment.sender_segment.seqno,
                            peer->sender.next_seqno) +
                   peer->rtx_queue.head->segment.sender_segment.len);

        if (peer->rtx_queue.head != peer->rtx_queue.tail) {
            printk(" | Last segment: %u-%u",
                   unwrap_seqno(peer->rtx_queue.tail->segment.sender_segment.seqno,
                                peer->sender.next_seqno),
                   unwrap_seqno(peer->rtx_queue.tail->segment.sender_segment.seqno,
                                peer->sender.next_seqno) +
                       peer->rtx_queue.tail->segment.sender_segment.len);
        }
        printk("\n");
    }
}

/**
 * Main file sender function
 */
static bool send_file_over_tcp(void) {
    printk("=== Starting TCP File Sender (Initiator) ===\n");

    // Initialize NRF interface
    printk("Initializing NRF interface...\n");
    uint32_t my_nrf_addr = rcp_to_nrf[MY_RCP_ADDR];
    printk("Configuring NRF=[%x] with %d byte msgs\n", my_nrf_addr, RCP_TOTAL_SIZE);

    nrf_t *nrf = client_mk_noack(my_nrf_addr, RCP_TOTAL_SIZE);
    if (!nrf) {
        printk("ERROR: Failed to initialize NRF interface\n");
        return false;
    }

    // Reset stats for tracking
    nrf_stat_start(nrf);

    // Initialize TCP peer
    printk("Initializing TCP peer...\n");
    tcp_peer_t peer = tcp_peer_init(nrf, MY_RCP_ADDR, PEER_RCP_ADDR, false);

    // Prepare file data
    size_t file_size = binary_length;
    uint32_t file_hash = fast_hash32(binary_data, file_size);
    printk("File to send: %u bytes, hash: %x\n", file_size, file_hash);

    // Start connection
    printk("Establishing TCP connection...\n");
    if (!tcp_connect(&peer)) {
        printk("ERROR: Failed to initialize connection\n");
        return false;
    }

    // Variables for tracking progress
    size_t bytes_written = 0;
    int iterations = 0;
    bool connection_closed = false;
    bool connection_established = false;
    printk("\n--- Starting File Transfer ---\n");

    // Main transfer loop
    while (tcp_is_active(&peer)) {
        // Process network events
        tcp_tick(&peer);
        delay_ms(TICK_DELAY_MS);
        iterations++;

        if (!connection_established && peer.sender.acked_seqno > 0) {
            connection_established = true;
            printk("\n\n>>>>>>> Connection established <<<<<<<\n\n");
        }

        // Try to send more data
        size_t remaining_to_send = file_size - bytes_written;
        if (remaining_to_send > 0 && tcp_has_space(&peer)) {
            size_t new_bytes_written =
                tcp_write(&peer, (uint8_t *)binary_data + bytes_written, remaining_to_send);
            bytes_written += new_bytes_written;
        }

        // Once all data is written, close the connection
        if (bytes_written == file_size && !connection_closed) {
            printk("All data written, closing connection...\n");
            tcp_close(&peer);
            connection_closed = true;
        }

        // Log progress periodically
        if (iterations % PROGRESS_INTERVAL == 0) {
            print_transfer_progress(&peer, bytes_written, file_size, iterations);
        }
    }

    // Final status
    printk("\n--- File Transfer Completed ---\n");
    print_transfer_progress(&peer, bytes_written, file_size, iterations);

    // Verify that all data was sent
    bool success = (bytes_written == file_size);
    if (success) {
        printk("SUCCESS: Full file of %u bytes transmitted\n", file_size);
    } else {
        printk("ERROR: Only sent %u/%u bytes\n", bytes_written, file_size);
    }

    // Print final statistics
    printk("\n=== TCP Connection Statistics ===\n");
    tcp_print_stats(&peer);

    // Print NRF statistics
    nrf_stat_print(nrf, "NRF stats");

    return success;
}

void notmain(void) {
    // Initialize memory allocator
    uint32_t MB = 1024 * 1024;
    uint32_t start_addr = 3 * MB;
    uint32_t heap_size = 64 * MB;
    kmalloc_init_set_start((void *)start_addr, heap_size);

    // Run the file transfer
    bool transfer_successful = send_file_over_tcp();

    if (transfer_successful) {
        printk("\nTCP FILE TRANSFER: PASSED\n");
    } else {
        printk("\nTCP FILE TRANSFER: FAILED\n");
    }
}