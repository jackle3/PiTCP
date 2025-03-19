/**
 * TCP Peer-to-Peer File Receiver
 *
 * This program runs on the responder side (server) and receives a file from the client.
 * It accepts a TCP connection, receives the file data, and verifies data integrity.
 */

#include <string.h>

#include "libc/fast-hash32.h"
#include "nrf-test.h"
#include "tcp.h"

// RCP and NRF addresses
#define MY_RCP_ADDR 0x2
#define PEER_RCP_ADDR 0x1

// Test parameters
#define PROGRESS_INTERVAL 1024           // How often to print progress (in ticks)
#define MAX_FILE_SIZE (4 * 1024 * 1024)  // 4MB maximum file size
// #define TICK_DELAY_MS 10                 // Delay between ticks in milliseconds

/**
 * Print file transfer progress
 */
static void print_transfer_progress(tcp_peer_t *peer, size_t bytes_received, int iterations) {
    printk("\n[RECEIVER] Transfer progress (iterations: %d, received: %u bytes):\n", iterations,
           bytes_received);

    // TCP status
    printk("[RECEIVER] TCP State: next_seqno=%u, latest_reasm=%u, window=%u\n",
           peer->receiver.next_seqno, peer->receiver.latest_seqno_in_reasm,
           peer->receiver.window_size);

    printk("[RECEIVER] Connection flags: syn=%d, fin=%d\n", peer->receiver.syn_received,
           peer->receiver.fin_received);

    // Connection state
    bool sender_active =
        !bs_reader_finished(&peer->sender.reader) || !tcp_rtx_empty(&peer->rtx_queue);
    bool receiver_active = !bs_writer_finished(&peer->receiver.writer);
    bool lingering = peer->lingering &&
                     (timer_get_usec() - peer->time_of_last_receipt_us < TIME_WAIT_DURATION_US);

    printk("[RECEIVER] Connection state: sender_active=%d, receiver_active=%d, lingering=%d\n",
           sender_active, receiver_active, lingering);
}

/**
 * Main file receiver function
 */
static bool receive_file_over_tcp(void) {
    printk("=== Starting TCP File Receiver (Server) ===\n");

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
    tcp_peer_t peer = tcp_peer_init(nrf, MY_RCP_ADDR, PEER_RCP_ADDR, true);

    // Allocate buffer for receiving the file
    uint8_t *file_buffer = kmalloc(MAX_FILE_SIZE);
    if (!file_buffer) {
        printk("ERROR: Failed to allocate file buffer\n");
        return false;
    }

    // Variables for tracking progress
    size_t bytes_received = 0;
    int iterations = 0;
    bool connection_closed = false;

    printk("\n--- Waiting for Incoming Connection ---\n");

    // Main receive loop
    while (tcp_is_active(&peer)) {
        // Process network events
        tcp_tick(&peer);
        // delay_ms(TICK_DELAY_MS);
        iterations++;

        // Check for incoming data
        size_t bytes_available = tcp_bytes_available(&peer);
        if (bytes_available > 0) {
            size_t bytes_read = tcp_read(&peer, file_buffer + bytes_received, bytes_available);
            bytes_received += bytes_read;
        }

        // If we've received a FIN, close our end of the connection
        if (peer.receiver.fin_received && !connection_closed) {
            printk("Received FIN, closing our end of the connection...\n");
            tcp_close(&peer);
            connection_closed = true;
        }

        // Log progress periodically
        if (iterations % PROGRESS_INTERVAL == 0) {
            print_transfer_progress(&peer, bytes_received, iterations);
        }
    }

    // Final status
    printk("\n--- File Transfer Completed ---\n");
    print_transfer_progress(&peer, bytes_received, iterations);

    // Calculate hash to verify file integrity
    if (bytes_received > 0) {
        uint32_t file_hash = fast_hash32(file_buffer, bytes_received);
        printk("Received file: %u bytes, hash: %x\n", bytes_received, file_hash);

        // In a real-world scenario, you would compare this hash with one provided by the sender
        // Here we just present it so it can be manually compared
        printk("NOTE: To verify integrity, compare this hash with the sender's hash\n");
    } else {
        printk("ERROR: No data received\n");
        return false;
    }

    // Print final statistics
    printk("\n=== TCP Connection Statistics ===\n");
    tcp_print_stats(&peer);

    // Print NRF statistics
    nrf_stat_print(nrf, "NRF stats");

    return true;
}

void notmain(void) {
    // Initialize memory allocator
    uint32_t MB = 1024 * 1024;
    uint32_t start_addr = 3 * MB;
    uint32_t heap_size = 64 * MB;
    kmalloc_init_set_start((void *)start_addr, heap_size);

    // Run the file receiver
    bool receive_successful = receive_file_over_tcp();

    if (receive_successful) {
        printk("\nTCP FILE RECEIVE: COMPLETED\n");
    } else {
        printk("\nTCP FILE RECEIVE: FAILED\n");
    }
}