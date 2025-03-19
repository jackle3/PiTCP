/**
 * TCP Loopback Test
 *
 * Tests the TCP implementation by creating a loopback connection
 * where a client and server communicate on the same Pi.
 *
 * This test treats TCP as a unified bytestream, where SYN and FIN
 * are simply part of the normal data flow rather than separate phases.
 */

#include <string.h>

#include "libc/fast-hash32.h"
#include "nrf-test.h"
#include "tcp.h"

// RCP addresses for client and server
#define CLIENT_RCP_ADDR 0x1
#define SERVER_RCP_ADDR 0x2

// NRF addresses for client and server
#define CLIENT_NRF_ADDR client_addr
#define SERVER_NRF_ADDR server_addr

// Test parameters
#define MAX_ITERATIONS 2000
#define TICK_DELAY_MS 10  // Delay between ticks in milliseconds

// Test data to send
// #include "byte-array-hello.h"
// #include "byte-array-small-file.h"
#include "byte-array-1mb-file.h"

/**
 * Helper function to run ticks on both TCP peers
 */
static void run_ticks(tcp_peer_t *client, tcp_peer_t *server, int count) {
    for (int i = 0; i < count; i++) {
        tcp_tick(client);
        tcp_tick(server);
        // delay_ms(TICK_DELAY_MS);
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
 * Print connection progress
 */
static void print_connection_progress(tcp_peer_t *client, tcp_peer_t *server, size_t bytes_written,
                                      size_t bytes_received, size_t message_len, int iterations) {
    printk("\nConnection progress (iterations: %d):\n", iterations);
    printk("  [CLIENT] Written: %u/%u bytes | [SERVER] Received: %u/%u bytes\n", bytes_written,
           message_len, bytes_received, message_len);

    // Client status
    printk("[CLIENT] Sender: seqno=%u, acked=%u, window=%u, in_flight=%u\n",
           client->sender.next_seqno, client->sender.acked_seqno, client->sender.window_size,
           client->segs_in_flight);

    if (client->segs_in_flight > 0) {
        printk("  First in flight: %u-%u",
               unwrap_seqno(client->rtx_queue.head->segment.sender_segment.seqno,
                            client->sender.next_seqno),
               unwrap_seqno(client->rtx_queue.head->segment.sender_segment.seqno,
                            client->sender.next_seqno) +
                   client->rtx_queue.head->segment.sender_segment.len);

        if (client->rtx_queue.head != client->rtx_queue.tail) {
            printk(" | Last: %u-%u",
                   unwrap_seqno(client->rtx_queue.tail->segment.sender_segment.seqno,
                                client->sender.next_seqno),
                   unwrap_seqno(client->rtx_queue.tail->segment.sender_segment.seqno,
                                client->sender.next_seqno) +
                       client->rtx_queue.tail->segment.sender_segment.len);
        }
        printk("\n");
    }

    printk("[CLIENT] Receiver: next=%u, latest_reasm=%u, window=%u, syn=%d, fin=%d\n",
           client->receiver.next_seqno, client->receiver.latest_seqno_in_reasm,
           client->receiver.window_size, client->receiver.syn_received,
           client->receiver.fin_received);

    // Connection state
    bool sender_active =
        !bs_reader_finished(&client->sender.reader) || !tcp_rtx_empty(&client->rtx_queue);
    bool receiver_active = !bs_writer_finished(&client->receiver.writer);
    bool lingering = client->lingering &&
                     (timer_get_usec() - client->time_of_last_receipt_us < TIME_WAIT_DURATION_US);
    printk("[CLIENT] State: sender_active=%d, receiver_active=%d, lingering=%d\n", sender_active,
           receiver_active, lingering);

    // Server status
    printk("[SERVER] Sender: seqno=%u, acked=%u, window=%u, in_flight=%u\n",
           server->sender.next_seqno, server->sender.acked_seqno, server->sender.window_size,
           server->segs_in_flight);

    if (server->segs_in_flight > 0) {
        printk("  First in flight: %u-%u",
               unwrap_seqno(server->rtx_queue.head->segment.sender_segment.seqno,
                            server->sender.next_seqno),
               unwrap_seqno(server->rtx_queue.head->segment.sender_segment.seqno,
                            server->sender.next_seqno) +
                   server->rtx_queue.head->segment.sender_segment.len);

        if (server->rtx_queue.head != server->rtx_queue.tail) {
            printk(" | Last: %u-%u",
                   unwrap_seqno(server->rtx_queue.tail->segment.sender_segment.seqno,
                                server->sender.next_seqno),
                   unwrap_seqno(server->rtx_queue.tail->segment.sender_segment.seqno,
                                server->sender.next_seqno) +
                       server->rtx_queue.tail->segment.sender_segment.len);
        }
        printk("\n");
    }

    printk("[SERVER] Receiver: next=%u, latest_reasm=%u, window=%u, syn=%d, fin=%d\n",
           server->receiver.next_seqno, server->receiver.latest_seqno_in_reasm,
           server->receiver.window_size, server->receiver.syn_received,
           server->receiver.fin_received);

    // Connection state
    sender_active =
        !bs_reader_finished(&server->sender.reader) || !tcp_rtx_empty(&server->rtx_queue);
    receiver_active = !bs_writer_finished(&server->receiver.writer);
    lingering = server->lingering &&
                (timer_get_usec() - server->time_of_last_receipt_us < TIME_WAIT_DURATION_US);
    printk("[SERVER] State: sender_active=%d, receiver_active=%d, lingering=%d\n", sender_active,
           receiver_active, lingering);
}

/**
 * Main loopback test function
 */
static bool test_tcp_loopback(void) {
    printk("=== Starting Unified TCP Loopback Test ===\n");

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

    // Initialize connection and prepare to send data
    printk("Starting unified TCP connection process...\n");

    // Connect client to server (this is just opening the stream)
    if (!tcp_connect(&client)) {
        printk("ERROR: Failed to initialize client connection\n");
        return false;
    }

    // Prepare data to send
    size_t message_len = binary_length;
    uint32_t hash_sent = fast_hash32(binary_data, message_len);
    printk("Data to send: %u bytes, hash: %x\n", message_len, hash_sent);

    // Initially write some data - the SYN will be automatically included in the first segment
    size_t bytes_written = tcp_write(&client, (uint8_t *)binary_data, message_len);
    printk("Client initially wrote %u/%u bytes\n", bytes_written, message_len);

    uint8_t receive_buffer[message_len];
    size_t bytes_received = 0;

    // Server is passive, close it's end of the connection because it will not send anything
    tcp_close(&server);

    // The main loop handles everything: connection establishment, data transfer, and termination
    printk("\n--- Starting Unified TCP Process ---\n");
    int iterations = 0;

    // Main connection loop: continues running until both endpoints have completed data transfer,
    // acknowledged all segments, and finished the connection teardown process.
    while (tcp_is_active(&client) || tcp_is_active(&server)) {
        // Client: Try to write any remaining data to the TCP connection
        // This will buffer data in the sender's bytestream for transmission
        size_t remaining_to_send = message_len - bytes_written;
        if (remaining_to_send > 0 && tcp_has_space(&client)) {
            size_t new_bytes_written =
                tcp_write(&client, binary_data + bytes_written, remaining_to_send);
            bytes_written += new_bytes_written;
        }

        // Client: Once all data is successfully written to the bytestream, initiate connection
        // termination. This signals the end of data transmission but allows the connection to
        // remain half-open for receiving data from the server until a proper TCP teardown completes
        if (bytes_written == message_len) {
            tcp_close(&client);
        }

        // Run network ticks
        run_ticks(&client, &server, 1);
        iterations++;

        // Server: Read any available data in server
        if (tcp_has_data(&server)) {
            size_t bytes_read = tcp_read(&server, receive_buffer + bytes_received,
                                         sizeof(receive_buffer) - bytes_received);
            bytes_received += bytes_read;
        }

        // Log progress periodically
        if (iterations % 20 == 0) {
            print_connection_progress(&client, &server, bytes_written, bytes_received, message_len,
                                      iterations);
        }
    }

    // Final status
    printk("\n--- Connection Completed ---\n");
    print_connection_progress(&client, &server, bytes_written, bytes_received, message_len,
                              iterations);

    // Verify data integrity
    if (bytes_received < message_len) {
        printk("ERROR: Data transfer failed. Server received %u/%u bytes\n", bytes_received,
               message_len);
        return false;
    }

    uint32_t hash_received = fast_hash32(receive_buffer, bytes_received);
    printk("Data verification: sent hash %x, received hash %x\n", hash_sent, hash_received);

    bool data_matches =
        (bytes_received == message_len && memcmp(receive_buffer, binary_data, message_len) == 0);

    if (data_matches && hash_received == hash_sent) {
        printk("Data verification: SUCCESS!\n");
    } else {
        printk("ERROR: Data verification failed\n");
        return false;
    }

    // Print final statistics
    printk("\n=== TCP Connection Statistics ===\n");
    printk("Client TCP Stats:\n");
    tcp_print_stats(&client);

    printk("\nServer TCP Stats:\n");
    tcp_print_stats(&server);

    // Print NRF statistics
    nrf_stat_print(client_nrf, "Client NRF stats");
    nrf_stat_print(server_nrf, "Server NRF stats");

    printk("=== TCP Loopback Test Completed Successfully ===\n");

    return true;
}

void notmain(void) {
    // Initialize memory allocator
    uint32_t MB = 1024 * 1024;
    uint32_t start_addr = 3 * MB;
    uint32_t heap_size = 64 * MB;
    kmalloc_init_set_start((void *)start_addr, heap_size);

    // Run the TCP loopback test
    bool test_successful = test_tcp_loopback();

    if (test_successful) {
        printk("\nTCP TEST: PASSED\n");
    } else {
        printk("\nTCP TEST: FAILED\n");
    }
}