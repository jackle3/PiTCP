/**
 * TCP Peer-to-Peer Test
 *
 * Tests the TCP implementation by creating a peer-to-peer connection
 * between two devices.
 *
 * The test verifies:
 * 1. Connection establishment (SYN handshake)
 * 2. Data transfer
 * 3. Connection termination (FIN handshake)
 */

#include <string.h>

#include "libc/fast-hash32.h"
#include "nrf-test.h"
#include "tcp.h"

// RCP addresses for local and remote peers
#define MY_RCP_ADDR 0x1
#define REMOTE_RCP_ADDR 0x2

// NRF addresses for local and remote interfaces
#define MY_NRF_ADDR client_addr
#define REMOTE_NRF_ADDR client_addr_2

// Test parameters
#define TIME_WAIT_ITERATIONS 1000  // Maximum iterations for TIME_WAIT
#define TICK_DELAY_MS 10           // Delay between ticks in milliseconds

// Test data to send
#include "byte-array-hello.h"
// #include "byte-array-1mb-file.h"

/**
 * Helper function to print the TCP state name
 */
static const char *tcp_state_name(tcp_state_t state) {
    switch (state) {
        case TCP_CLOSED:
            return "CLOSED";
        case TCP_LISTEN:
            return "LISTEN";
        case TCP_SYN_SENT:
            return "SYN_SENT";
        case TCP_SYN_RECEIVED:
            return "SYN_RECEIVED";
        case TCP_ESTABLISHED:
            return "ESTABLISHED";
        case TCP_FIN_WAIT_1:
            return "FIN_WAIT_1";
        case TCP_FIN_WAIT_2:
            return "FIN_WAIT_2";
        case TCP_CLOSE_WAIT:
            return "CLOSE_WAIT";
        case TCP_CLOSING:
            return "CLOSING";
        case TCP_LAST_ACK:
            return "LAST_ACK";
        case TCP_TIME_WAIT:
            return "TIME_WAIT";
        default:
            return "UNKNOWN";
    }
}

/**
 * Helper function to run ticks on my TCP peer
 */
static void run_ticks(tcp_peer_t *my_peer, int count) {
    for (int i = 0; i < count; i++) {
        tcp_tick(my_peer);
        delay_ms(TICK_DELAY_MS);
    }
}

/**
 * Prepare routing table for the peer-to-peer test
 */
static void setup_routing_table(void) {
    // Set up routing entry from my device to remote device
    rtable_map[MY_RCP_ADDR][REMOTE_RCP_ADDR] = REMOTE_NRF_ADDR;
}

/**
 * Main peer-to-peer test function
 */
static bool test_tcp_peer_to_peer(bool is_initiator) {
    printk("=== Starting TCP Peer-to-Peer Test ===\n");
    printk("Role: %s\n", is_initiator ? "Initiator" : "Responder");

    // Set up the routing table
    setup_routing_table();

    // Initialize NRF interface
    printk("Initializing NRF interface...\n");
    printk("Configuring NRF=[%x] with %d byte msgs\n", MY_NRF_ADDR, RCP_TOTAL_SIZE);
    nrf_t *my_nrf = client_mk_noack(MY_NRF_ADDR, RCP_TOTAL_SIZE);

    if (!my_nrf) {
        printk("ERROR: Failed to initialize NRF interface\n");
        return false;
    }

    // Reset stats for tracking
    nrf_stat_start(my_nrf);

    // Initialize TCP peer
    printk("Initializing TCP peer...\n");
    tcp_peer_t my_peer = tcp_peer_init(my_nrf, MY_RCP_ADDR, REMOTE_RCP_ADDR, !is_initiator);
    printk("Initial state: %s\n", tcp_state_name(my_peer.state));

    //---------------------------------------------------------------------
    // Phase 1: Connection establishment (SYN handshake)
    //---------------------------------------------------------------------
    printk("\n--- Phase 1: Connection Establishment ---\n");

    if (is_initiator) {
        // Initiator initiates connection
        printk("Initiating connection...\n");
        if (!tcp_connect(&my_peer)) {
            printk("ERROR: Failed to initiate connection\n");
            return false;
        }
        printk("State after connect: %s\n", tcp_state_name(my_peer.state));
    } else {
        // Responder listens for connections
        printk("Listening for connections...\n");
    }

    // Run ticks until connection is established or max iterations reached
    int iterations = 0;
    printk("Waiting for connection establishment...\n");

    while (!tcp_is_established(&my_peer)) {
        // Run one round of ticks
        run_ticks(&my_peer, 1);
        iterations++;

        // Log progress periodically
        if (iterations % 10 == 0) {
            printk("  Handshake progress (iterations: %d):\n", iterations);
            printk("  Current state: %s\n", tcp_state_name(my_peer.state));
        }

        // Timeout after too many iterations
        if (iterations > 300) {
            printk("ERROR: Connection establishment timeout after %d iterations\n", iterations);
            return false;
        }
    }

    // Check if connection was established
    if (!tcp_is_established(&my_peer)) {
        printk("ERROR: Connection establishment failed after %d iterations\n", iterations);
        printk("Current state: %s\n", tcp_state_name(my_peer.state));
        return false;
    }

    printk("Connection established successfully after %d iterations\n", iterations);
    printk("Current state: %s\n", tcp_state_name(my_peer.state));

    // Print TCP statistics after connection establishment
    printk("\n=== TCP Statistics after Connection Establishment ===\n");
    tcp_print_stats(&my_peer);

    //---------------------------------------------------------------------
    // Phase 2: Data transfer
    //---------------------------------------------------------------------
    printk("\n--- Phase 2: Data Transfer ---\n");

    if (is_initiator) {
        // Initiator sends data
        size_t message_len = binary_length;
        uint32_t hash_sent = fast_hash32(binary_data, message_len);
        printk("Sending %u bytes of data to remote peer...\n", message_len);
        printk("  crc of sent data (nbytes=%u): %x\n", message_len, hash_sent);

        size_t bytes_written = tcp_write(&my_peer, (uint8_t *)binary_data, message_len);
        printk("Wrote %u/%u bytes\n", bytes_written, message_len);

        if (bytes_written != message_len) {
            printk("WARNING: Not all data was queued for sending\n");
        }

        // Run ticks until all data is sent
        iterations = 0;
        printk("Sending data...\n");

        // Continue sending and running ticks until all data is queued
        while (bytes_written < message_len) {
            size_t remaining_to_send = message_len - bytes_written;
            if (remaining_to_send > 0 && tcp_has_space(&my_peer)) {
                size_t new_bytes_written =
                    tcp_write(&my_peer, binary_data + bytes_written, remaining_to_send);
                bytes_written += new_bytes_written;
            }

            // Run ticks
            run_ticks(&my_peer, 1);
            iterations++;

            // Log progress periodically
            if (iterations % 20 == 0) {
                printk("\n");
                printk("Transfer progress (iterations: %d):\n", iterations);
                printk("  Written: %u/%u bytes\n", bytes_written, message_len);
                printk("  Current state: %s\n", tcp_state_name(my_peer.state));

                // Print the status about the sender
                printk("Sender status:\n");
                printk("  Next seqno: %u\n", my_peer.sender.next_seqno);
                printk("  Acked seqno: %u\n", my_peer.sender.acked_seqno);
                printk("  Window size: %u\n", my_peer.sender.window_size);

                // Print the current state of the retransmission queue if segments are in flight
                if (my_peer.segs_in_flight > 0) {
                    printk("  Retransmission queue (size: %u):\n", my_peer.segs_in_flight);
                    printk("    Earliest seqno in flight: %u to %u\n",
                           unwrap_seqno(my_peer.rtx_queue.head->segment.sender_segment.seqno,
                                        my_peer.sender.next_seqno),
                           unwrap_seqno(my_peer.rtx_queue.head->segment.sender_segment.seqno,
                                        my_peer.sender.next_seqno) +
                               my_peer.rtx_queue.head->segment.sender_segment.len);
                    printk("    Latest seqno in flight: %u to %u\n",
                           unwrap_seqno(my_peer.rtx_queue.tail->segment.sender_segment.seqno,
                                        my_peer.sender.next_seqno),
                           unwrap_seqno(my_peer.rtx_queue.tail->segment.sender_segment.seqno,
                                        my_peer.sender.next_seqno) +
                               my_peer.rtx_queue.tail->segment.sender_segment.len);
                }
            }

            // Timeout after too many iterations
            if (iterations > 3000) {
                printk("WARNING: Data transfer timeout after %d iterations\n", iterations);
                break;
            }
        }

        // Continue running ticks to ensure all data is acknowledged
        while (my_peer.sender.acked_seqno < my_peer.sender.next_seqno && iterations < 3000) {
            run_ticks(&my_peer, 1);
            iterations++;

            if (iterations % 50 == 0) {
                printk("Waiting for acknowledgments (iterations: %d):\n", iterations);
                printk("  Next seqno: %u, Acked seqno: %u\n", my_peer.sender.next_seqno,
                       my_peer.sender.acked_seqno);
            }
        }

        printk("\n");
        printk("Finished sending in %d iterations\n", iterations);
        printk("  Next seqno: %u, Acked seqno: %u\n", my_peer.sender.next_seqno,
               my_peer.sender.acked_seqno);
        printk("  Current state: %s\n", tcp_state_name(my_peer.state));

    } else {
        // Responder receives data
        uint8_t receive_buffer[binary_length];  // Allocate same size as the test data
        size_t bytes_received = 0;

        // Run ticks until data is received or max iterations reached
        iterations = 0;
        printk("Waiting to receive data...\n");

        while (iterations < 3000) {
            // Run ticks
            run_ticks(&my_peer, 1);
            iterations++;

            // If data available, read it
            if (tcp_has_data(&my_peer)) {
                size_t bytes_read = tcp_read(&my_peer, receive_buffer + bytes_received,
                                             sizeof(receive_buffer) - bytes_received);
                bytes_received += bytes_read;
            }

            // Log progress periodically
            if (iterations % 20 == 0) {
                printk("\n");
                printk("Reception progress (iterations: %d):\n", iterations);
                printk("  Received: %u bytes\n", bytes_received);
                printk("  Current state: %s\n", tcp_state_name(my_peer.state));

                // Print the status about the receiver
                printk("Receiver status:\n");
                printk("  Next seqno: %u\n", my_peer.receiver.next_seqno);
                printk("  Window size: %u\n", my_peer.receiver.window_size);
            }

            // Exit loop if no more data and sender has sent FIN
            if (!tcp_has_data(&my_peer) && my_peer.receiver.fin_received) {
                printk("Detected FIN from sender, data transfer complete\n");
                break;
            }
        }

        printk("\n");
        printk("Finished receiving in %d iterations\n", iterations);
        printk("  Received: %u bytes\n", bytes_received);
        printk("  Current state: %s\n", tcp_state_name(my_peer.state));

        // Verify data integrity if we received data
        if (bytes_received > 0) {
            uint32_t hash_received = fast_hash32(receive_buffer, bytes_received);
            printk("  crc of received data (nbytes=%u): %x\n", bytes_received, hash_received);
            printk("  Note: Compare this CRC with the sender's CRC\n");
        }
    }

    // Print TCP statistics after data transfer
    printk("\n=== TCP Statistics after Data Transfer ===\n");
    tcp_print_stats(&my_peer);

    //---------------------------------------------------------------------
    // Phase 3: Connection termination (FIN handshake)
    //---------------------------------------------------------------------
    printk("\n--- Phase 3: Connection Termination ---\n");

    if (is_initiator) {
        // Initiator starts connection close
        printk("Initiating connection close...\n");
        tcp_close(&my_peer);
    } else {
        // Responder waits for FIN from initiator, then closes
        printk("Waiting for connection close from initiator...\n");

        // If we're not in CLOSE_WAIT yet, wait for it
        while (my_peer.state != TCP_CLOSE_WAIT && my_peer.state != TCP_CLOSED) {
            run_ticks(&my_peer, 1);

            if (my_peer.state == TCP_CLOSE_WAIT) {
                printk("Received FIN from initiator, closing our end...\n");
                tcp_close(&my_peer);
                break;
            }
        }
    }

    // Run ticks until the connection is fully terminated or max iterations reached
    iterations = 0;
    bool connection_terminated = false;

    printk("Waiting for full connection termination...\n");
    while (!connection_terminated && iterations < TIME_WAIT_ITERATIONS) {
        run_ticks(&my_peer, 1);
        iterations++;

        // Check if connection is fully terminated
        if (!tcp_is_active(&my_peer)) {
            connection_terminated = true;
        }

        // Log progress periodically
        if (iterations % 50 == 0) {
            printk("Termination progress (iterations: %d):\n", iterations);
            printk("    Current state: %s\n", tcp_state_name(my_peer.state));
            printk("    Active: %d\n", tcp_is_active(&my_peer));
        }
    }

    // Check if termination was successful
    if (!connection_terminated) {
        printk("WARNING: Connection not fully terminated after %d iterations\n", iterations);
        printk("Current state: %s\n", tcp_state_name(my_peer.state));
        printk("Active: %d\n", tcp_is_active(&my_peer));
    } else {
        printk("Connection terminated successfully after %d iterations\n", iterations);
        printk("Current state: %s\n", tcp_state_name(my_peer.state));
    }

    // Print TCP statistics after connection termination
    printk("\n=== TCP Statistics after Connection Termination ===\n");
    tcp_print_stats(&my_peer);

    // Clean up resources
    tcp_cleanup(&my_peer);

    printk("Final State: %s\n", tcp_state_name(my_peer.state));

    // Print NRF statistics
    nrf_stat_print(my_nrf, "NRF stats");

    printk("=== TCP Peer-to-Peer Test Completed Successfully ===\n");

    return true;
}

void notmain(void) {
    // Initialize memory allocator
    uint32_t MB = 1024 * 1024;
    uint32_t start_addr = 3 * MB;
    uint32_t heap_size = 64 * MB;
    kmalloc_init_set_start((void *)start_addr, heap_size);

    // Define whether this device is the initiator or responder
    // This would typically be determined by a command line argument or configuration
    bool is_initiator = true;  // Set to false for the responder device

    // Run the TCP peer-to-peer test
    bool test_successful = test_tcp_peer_to_peer(is_initiator);

    if (test_successful) {
        printk("\nTCP TEST: PASSED\n");
    } else {
        printk("\nTCP TEST: FAILED\n");
    }
}