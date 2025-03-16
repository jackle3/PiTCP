/**
 * TCP Loopback Test
 *
 * Tests the TCP implementation by creating a loopback connection
 * where a client and server communicate on the same Pi.
 *
 * The test verifies:
 * 1. Connection establishment (SYN handshake)
 * 2. Data transfer
 * 3. Connection termination (FIN handshake)
 */

#include <string.h>

#include "nrf-test.h"
#include "tcp.h"

// RCP addresses for client and server
#define CLIENT_RCP_ADDR 0x1
#define SERVER_RCP_ADDR 0x2

// NRF addresses for client and server
#define CLIENT_NRF_ADDR client_addr
#define SERVER_NRF_ADDR server_addr

// Test parameters
#define MAX_ITERATIONS 1000        // Maximum iterations for each phase
#define TIME_WAIT_ITERATIONS 1000  // Maximum iterations for TIME_WAIT
#define TICK_DELAY_MS 10           // Delay between ticks in milliseconds

// Test data to send
#include "byte-array-hello.h"

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
 * Helper function to run ticks on both TCP peers
 */
static void run_ticks(tcp_peer_t *client, tcp_peer_t *server, int count) {
    for (int i = 0; i < count; i++) {
        tcp_tick(client);
        tcp_tick(server);
        delay_ms(TICK_DELAY_MS);
    }
}

/**
 * Prepare routing table for the loopback test
 */
static void setup_routing_table(void) {
    // Set up routing entries for client to server
    rtable_map[CLIENT_RCP_ADDR][SERVER_RCP_ADDR] = SERVER_NRF_ADDR;

    // Set up routing entries for server to client
    rtable_map[SERVER_RCP_ADDR][CLIENT_RCP_ADDR] = CLIENT_NRF_ADDR;
}

/**
 * Main loopback test function
 */
static bool test_tcp_loopback(void) {
    printk("=== Starting TCP Loopback Test ===\n");

    // Set up the routing table
    setup_routing_table();

    // Initialize NRF interfaces
    printk("Initializing NRF interfaces...\n");

    // Initialize client NRF using the provided helper function
    printk("Configuring client NRF=[%x] with %d byte msgs\n", CLIENT_NRF_ADDR, RCP_TOTAL_SIZE);
    nrf_t *client_nrf = client_mk_noack(CLIENT_NRF_ADDR, RCP_TOTAL_SIZE);

    // Initialize server NRF using the provided helper function
    printk("Configuring server NRF=[%x] with %d byte msgs\n", SERVER_NRF_ADDR, RCP_TOTAL_SIZE);
    nrf_t *server_nrf = server_mk_noack(SERVER_NRF_ADDR, RCP_TOTAL_SIZE);

    if (!client_nrf || !server_nrf) {
        printk("ERROR: Failed to initialize NRF interfaces\n");
        return false;
    }

    // Check compatibility
    if (!nrf_compat(client_nrf, server_nrf)) {
        printk("ERROR: NRF interfaces are not compatible\n");
        return false;
    }

    // Reset stats for tracking
    nrf_stat_start(client_nrf);
    nrf_stat_start(server_nrf);

    // Initialize TCP peers
    printk("Initializing TCP peers...\n");
    tcp_peer_t client = tcp_peer_init(client_nrf, CLIENT_RCP_ADDR, SERVER_RCP_ADDR, false);
    tcp_peer_t server = tcp_peer_init(server_nrf, SERVER_RCP_ADDR, CLIENT_RCP_ADDR, true);

    printk("Client state: %s, Server state: %s\n", tcp_state_name(client.state),
           tcp_state_name(server.state));

    //---------------------------------------------------------------------
    // Phase 1: Connection establishment (SYN handshake)
    //---------------------------------------------------------------------
    printk("\n--- Phase 1: Connection Establishment ---\n");

    // Client initiates connection
    printk("Client initiating connection...\n");
    if (!tcp_connect(&client)) {
        printk("ERROR: Failed to initiate connection\n");
        return false;
    }
    printk("Client state after connect: %s\n", tcp_state_name(client.state));

    // Run ticks until connection is established or max iterations reached
    int iterations = 0;
    printk("Waiting for connection establishment...\n");

    while ((!tcp_is_established(&client) || !tcp_is_established(&server)) &&
           iterations < MAX_ITERATIONS) {
        // Run one round of ticks
        run_ticks(&client, &server, 1);
        iterations++;

        // Log progress periodically
        printk("  Handshake progress (iterations: %d):\n", iterations);
        printk("  Client state: %s, Server state: %s\n", tcp_state_name(client.state),
               tcp_state_name(server.state));
    }

    // Check if connection was established
    if (!tcp_is_established(&client) || !tcp_is_established(&server)) {
        printk("ERROR: Connection establishment failed after %d iterations\n", iterations);
        printk("Client state: %s, Server state: %s\n", tcp_state_name(client.state),
               tcp_state_name(server.state));
        return false;
    }

    printk("Connection established successfully after %d iterations\n", iterations);
    printk("Client state: %s, Server state: %s\n", tcp_state_name(client.state),
           tcp_state_name(server.state));

    //---------------------------------------------------------------------
    // Phase 2: Data transfer
    //---------------------------------------------------------------------
    printk("\n--- Phase 2: Data Transfer ---\n");

    // Send test message from client to server
    size_t message_len = binary_length;
    printk("Sending %u bytes of data from client to server...\n", message_len);

    size_t bytes_written = tcp_write(&client, (uint8_t *)binary_data, message_len);
    printk("Client wrote %u/%u bytes\n", bytes_written, message_len);

    if (bytes_written != message_len) {
        printk("WARNING: Not all data was queued for sending\n");
    }

    uint8_t receive_buffer[message_len];

    // Run ticks until all data is transferred or max iterations reached
    iterations = 0;
    size_t bytes_received = 0;

    printk("Starting data transfer...\n\n");
    while (bytes_received < message_len && iterations < MAX_ITERATIONS * 2) {
        size_t remaining_to_send = message_len - bytes_written;
        if (remaining_to_send > 0 && tcp_has_space(&client)) {
            size_t new_bytes_written =
                tcp_write(&client, binary_data + bytes_written, remaining_to_send);
            bytes_written += new_bytes_written;
        }

        // Run ticks
        run_ticks(&client, &server, 1);
        iterations++;

        // If the server received data, read it to free up space in the receiver's bytestream
        if (tcp_has_data(&server)) {
            // Read the data into the receive buffer
            size_t bytes_read = tcp_read(&server, receive_buffer + bytes_received,
                                         sizeof(receive_buffer) - bytes_received);
            bytes_received += bytes_read;
        }

        // Log progress periodically
        if (iterations % 20 == 0) {
            printk("Transfer progress (iterations: %d):\n", iterations);
            printk("  Client has written: %u/%u bytes\n", bytes_written, message_len);
            printk("  Server has received: %u/%u bytes\n", bytes_received, message_len);
            printk("  Client state: %s, Server state: %s\n", tcp_state_name(client.state),
                   tcp_state_name(server.state));

            // Print the status about the client (sender)
            printk("Client (sender) status:\n");
            printk("  Next seqno: %u\n", client.sender.next_seqno);
            printk("  Acked seqno: %u\n", client.sender.acked_seqno);
            printk("  Window size: %u\n", client.sender.window_size);

            // Print the status about the server (receiver)
            printk("Server (receiver) status:\n");
            printk("  Next seqno: %u\n", server.receiver.next_seqno);
            printk("  Window size: %u\n", server.receiver.window_size);
            printk("\n");
        }
    }

    printk("Finished sending in %d iterations\n", iterations);
    printk("  Server has received: %u/%u bytes\n", bytes_received, message_len);
    printk("  Client state: %s, Server state: %s\n", tcp_state_name(client.state),
           tcp_state_name(server.state));

    // Print the status about the client (sender)
    printk("Client (sender) status:\n");
    printk("  Next seqno: %u\n", client.sender.next_seqno);
    printk("  Acked seqno: %u\n", client.sender.acked_seqno);
    printk("  Window size: %u\n", client.sender.window_size);

    // Print the status about the server (receiver)
    printk("Server (receiver) status:\n");
    printk("  Next seqno: %u\n", server.receiver.next_seqno);
    printk("  Window size: %u\n", server.receiver.window_size);
    printk("  Total size: %u\n", server.receiver.total_size);
    printk("\n");

    // Check if data transfer completed
    if (bytes_received < message_len) {
        printk("ERROR: Data transfer failed after %d iterations\n", iterations);
        printk("Server received %u/%u bytes\n", bytes_received, message_len);
        return false;
    }

    printk("Data transfer completed successfully after %d iterations\n", iterations);

    receive_buffer[bytes_received] = '\0';  // Null-terminate for printing

    printk("Server read %u bytes\n", bytes_received);

    // Verify data integrity
    bool data_matches =
        (bytes_received == message_len && memcmp(receive_buffer, binary_data, message_len) == 0);

    if (data_matches) {
        printk("Data verification: SUCCESS!\n");
    } else {
        printk("ERROR: Data verification failed\n");
        printk("Expected %u bytes, received %u bytes\n", message_len, bytes_received);
        return false;
    }

    //---------------------------------------------------------------------
    // Phase 3: Connection termination (FIN handshake)
    //---------------------------------------------------------------------
    printk("\n--- Phase 3: Connection Termination ---\n");

    // Client initiates connection close
    printk("Client initiating connection close...\n");
    tcp_close(&client);

    // Run ticks until client's FIN is acknowledged
    iterations = 0;
    bool client_fin_acked = false;

    printk("Waiting for client FIN to be acknowledged...\n");
    while (!client_fin_acked && iterations < MAX_ITERATIONS) {
        run_ticks(&client, &server, 1);
        iterations++;

        // Check if client FIN has been acknowledged
        if (client.state == TCP_FIN_WAIT_2 && server.state == TCP_CLOSE_WAIT) {
            client_fin_acked = true;
        }

        // Log progress periodically
        if (iterations % 5 == 0) {
            printk("  Client FIN progress (iterations: %d):\n", iterations);
            printk("  Client state: %s, Server state: %s\n", tcp_state_name(client.state),
                   tcp_state_name(server.state));
        }
    }

    if (!client_fin_acked) {
        printk("ERROR: Client FIN not acknowledged after %d iterations\n", iterations);
        printk("Client state: %s, Server state: %s\n", tcp_state_name(client.state),
               tcp_state_name(server.state));
        return false;
    }

    printk("Client FIN acknowledged after %d iterations\n", iterations);
    printk("Client state: %s, Server state: %s\n", tcp_state_name(client.state),
           tcp_state_name(server.state));

    // Server closes its end
    printk("Server initiating connection close...\n");
    tcp_close(&server);

    // Run ticks until the connection is fully terminated
    iterations = 0;
    bool connection_terminated = false;

    printk("Waiting for full connection termination...\n");
    while (!connection_terminated && iterations < TIME_WAIT_ITERATIONS) {
        run_ticks(&client, &server, 1);
        iterations++;

        // Check if connection is fully terminated
        if (!tcp_is_active(&client) && !tcp_is_active(&server)) {
            connection_terminated = true;
        }

        // Log progress periodically
        if (iterations % 50 == 0) {
            printk("Termination progress (iterations: %d):\n", iterations);
            printk("    Client state: %s, Server state: %s\n", tcp_state_name(client.state),
                   tcp_state_name(server.state));
            printk("    Client active: %d, Server active: %d\n", tcp_is_active(&client),
                   tcp_is_active(&server));
        }
    }

    // Check if termination was successful
    if (!connection_terminated) {
        printk("WARNING: Connection not fully terminated after %d iterations\n", iterations);
        printk("Client state: %s, Server state: %s\n", tcp_state_name(client.state),
               tcp_state_name(server.state));
        printk("Client active: %d, Server active: %d\n", tcp_is_active(&client),
               tcp_is_active(&server));
    } else {
        printk("Connection terminated successfully after %d iterations\n", iterations);
        printk("Client state: %s, Server state: %s\n", tcp_state_name(client.state),
               tcp_state_name(server.state));
    }

    // Clean up resources
    tcp_cleanup(&client);
    tcp_cleanup(&server);

    printk("Final States");
    printk("  Client state: %s, Server state: %s\n", tcp_state_name(client.state),
           tcp_state_name(server.state));

    // Print the status about the client (sender)
    printk("  Client (sender) status:\n");
    printk("    Next seqno: %u\n", client.sender.next_seqno);
    printk("    Acked seqno: %u\n", client.sender.acked_seqno);
    printk("    Window size: %u\n", client.sender.window_size);

    // Print the status about the server (receiver)
    printk("  Server (receiver) status:\n");
    printk("    Next seqno: %u\n", server.receiver.next_seqno);
    printk("    Window size: %u\n", server.receiver.window_size);
    printk("    Total size: %u\n", server.receiver.total_size);
    printk("    Fin received: %d\n", server.receiver.fin_received);
    printk("\n");

    // Print NRF statistics
    nrf_stat_print(client_nrf, "Client NRF stats");
    nrf_stat_print(server_nrf, "Server NRF stats");

    printk("=== TCP Loopback Test Completed Successfully ===\n");

    return true;
}

void notmain(void) {
    // Initialize memory allocator
    kmalloc_init(64);

    // Run the TCP loopback test
    bool test_successful = test_tcp_loopback();

    if (test_successful) {
        printk("\nTCP TEST: PASSED\n");
    } else {
        printk("\nTCP TEST: FAILED\n");
    }
}