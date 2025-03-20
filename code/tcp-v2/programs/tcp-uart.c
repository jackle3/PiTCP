/**
 * TCP Chat Application
 *
 * This program allows two peers to chat with each other via UART over a TCP connection.
 * Messages typed in UART are sent to the other peer, and received messages are displayed.
 */

#include <stdlib.h>
#include <string.h>

#include "libc/fast-hash32.h"
#include "nrf-test.h"
#include "tcp.h"

// Buffer sizes
#define UART_BUFFER_SIZE 4096
#define TCP_READ_BUFFER_SIZE 4096  // hopefully user won't send more than this
#define TICK_DELAY_MS 5            // Delay between ticks in milliseconds

// Command definitions
#define CMD_QUIT ":quit"
#define CMD_STATS ":stats"

/**
 * Display TCP connection statistics
 */
static void print_tcp_stats(tcp_peer_t *peer) {
    printk("\n=== TCP Connection Statistics ===\n");

    // Sender stats
    printk("Sender:\n");
    printk("  Sequence number: %u\n", peer->sender.next_seqno);
    printk("  Last ACK: %u\n", peer->sender.acked_seqno);
    printk("  Window size: %u\n", peer->sender.window_size);
    printk("  Segments in flight: %u\n", peer->segs_in_flight);

    // Receiver stats
    printk("Receiver:\n");
    printk("  Next expected sequence: %u\n", peer->receiver.next_seqno);
    printk("  Window size: %u\n", peer->receiver.window_size);
    printk("  SYN received: %s\n", peer->receiver.syn_received ? "yes" : "no");
    printk("  FIN received: %s\n", peer->receiver.fin_received ? "yes" : "no");

    // Connection state
    bool sender_active =
        !bs_reader_finished(&peer->sender.reader) || !tcp_rtx_empty(&peer->rtx_queue);
    bool receiver_active = !bs_writer_finished(&peer->receiver.writer);
    bool lingering = peer->lingering &&
                     (timer_get_usec() - peer->time_of_last_receipt_us < TIME_WAIT_DURATION_US);

    printk("Connection state:\n");
    printk("  Sender active: %s\n", sender_active ? "yes" : "no");
    printk("  Receiver active: %s\n", receiver_active ? "yes" : "no");
    printk("  Lingering: %s\n", lingering ? "yes" : "no");
}

/**
 * Handle a complete line of input from UART
 * Returns true if the chat should continue, false if it should exit
 */
static bool handle_input_line(tcp_peer_t *peer, char *buffer, size_t length) {
    // Check for command
    if (length > 0 && buffer[0] == ':') {
        // Check for quit command
        if (strncmp(buffer, CMD_QUIT, strlen(CMD_QUIT)) == 0) {
            printk("Quit requested\n");
            return false;
        }

        // Check for stats command
        if (strncmp(buffer, CMD_STATS, strlen(CMD_STATS)) == 0) {
            print_tcp_stats(peer);
            return true;
        }

        // Unknown command
        printk("Unknown command: %s\n", buffer);
        printk("Available commands: %s, %s\n", CMD_QUIT, CMD_STATS);
        return true;
    }

    // Echo the message back to the user for debugging
    // printk("Sending message: %s\n", buffer);

    // Regular message - write the input to the TCP connection
    size_t bytes_written = tcp_write(peer, (uint8_t *)buffer, length);

    if (bytes_written < length) {
        printk("WARNING: Only wrote %u/%u bytes\n", bytes_written, length);
    }

    return true;
}

// Mini helper atoi
uint8_t my_atoi(const char *str) {
    uint8_t result = 0;

    // Skip leading whitespaces
    while (*str == ' ' || *str == '\t' || *str == '\n') {
        str++;
    }

    // Convert characters to integer
    while (*str >= '0' && *str <= '9') {
        result = result * 10 + (*str - '0');
        str++;
    }

    return result;
}

/**
 * Get a number from UART
 */
static uint8_t get_number_from_uart(void) {
    char buffer[16];
    size_t pos = 0;

    while (1) {
        // Wait for data
        while (!uart_has_data()) {
            // Just wait
        }

        char c = uart_get8();

        if (c == '\r' || c == '\n') {
            buffer[pos] = '\0';
            break;
        }

        if (pos < sizeof(buffer) - 1) {
            buffer[pos++] = c;
        }
    }

    return my_atoi(buffer);
}

/**
 * Main chat application
 */
static void run_tcp_chat(void) {
    printk("=== Starting TCP Chat Application ===\n");

    // Initialize UART
    uart_init();
    printk("UART initialized\n");

    // Get RCP addresses from user
    printk("Enter your RCP address (0 to 255): ");
    uint8_t my_rcp_addr = get_number_from_uart();

    printk("Enter destination RCP address (0 to 255): ");
    uint8_t peer_rcp_addr = get_number_from_uart();

    printk("Using RCP addresses: local=%u (0x%x), remote=%u (0x%x)\n", my_rcp_addr, my_rcp_addr,
           peer_rcp_addr, peer_rcp_addr);

    // Initialize NRF interface
    printk("Initializing NRF interface...\n");
    uint32_t my_nrf_addr = rcp_to_nrf[my_rcp_addr];
    printk("Configuring NRF=[%x] with %d byte msgs\n", my_nrf_addr, RCP_TOTAL_SIZE);
    nrf_t *nrf = client_mk_noack(my_nrf_addr, RCP_TOTAL_SIZE);
    if (!nrf) {
        printk("ERROR: Failed to initialize NRF interface\n");
        return;
    }

    // Reset stats for tracking
    nrf_stat_start(nrf);

    // Initialize TCP peer
    printk("Initializing TCP peer...\n");
    bool is_server = (my_rcp_addr > peer_rcp_addr);  // Higher address acts as server
    tcp_peer_t peer = tcp_peer_init(nrf, my_rcp_addr, peer_rcp_addr, is_server);

    // Welcome message
    printk("\n\n=== TCP Chat Application ===\n");
    printk("Type messages and press Enter to send.\n");
    printk("Commands: %s to exit, %s to show statistics\n\n", CMD_QUIT, CMD_STATS);

    // If this peer is the client, initiate connection
    if (!is_server) {
        printk("Establishing TCP connection as client...\n");
        if (!tcp_connect(&peer)) {
            printk("ERROR: Failed to initialize connection\n");
            return;
        }
        printk("Connecting to peer %u...\n", peer_rcp_addr);

        while (tcp_is_active(&peer)) {
            tcp_tick(&peer);
            delay_ms(TICK_DELAY_MS);

            // Client: once we've sent a SYN and received an ACK, connection is established
            if (peer.sender.acked_seqno > 0) {
                break;
            }
        }
    } else {
        printk("Waiting for peer %u to connect...\n", peer_rcp_addr);
        while (tcp_is_active(&peer)) {
            tcp_tick(&peer);
            delay_ms(TICK_DELAY_MS);

            // Server: once we've received a SYN from client and sent our own SYN
            if (peer.receiver.syn_received && peer.sender.next_seqno > 0) {
                break;
            }
        }
    }

    printk("\n\n>>>>>>> Connection established <<<<<<<\n\n");

    // Buffers for UART input and TCP receive
    char uart_buffer[UART_BUFFER_SIZE];
    size_t uart_buffer_pos = 0;

    uint8_t tcp_buffer[TCP_READ_BUFFER_SIZE];

    // Main loop variables
    bool quit_requested = false;

    size_t output_buffer_pos = 0;

    // Main chat loop
    while (tcp_is_active(&peer) && !quit_requested) {
        // Process network events
        tcp_tick(&peer);
        delay_ms(TICK_DELAY_MS);

        // Check for incoming UART data
        if (uart_has_data()) {
            printk("UART has data\n");
            while (1) {
                char c = uart_get8();

                // Add the line to the buffer before checking for newline
                // -> newline will be included in the sent message
                uart_buffer[uart_buffer_pos++] = c;
                if (uart_buffer_pos >= UART_BUFFER_SIZE - 1) {
                    break;
                }

                if (c == '\r' || c == '\n') {
                    delay_us(100);
                    if (!uart_has_data()) {
                        break;
                    }
                }
            }
        }

        // Handle the input line (either command or insert into TCP to send)
        if (uart_buffer_pos > 0) {
            printk("Handling input line\n");
            bool continue_chat = handle_input_line(&peer, uart_buffer, uart_buffer_pos);
            if (!continue_chat) {
                quit_requested = true;
                break;
            }
            // Reset buffer
            uart_buffer_pos = 0;
        }

        // Read data from TCP
        size_t bytes_read = tcp_read(&peer, tcp_buffer + output_buffer_pos,
                                     TCP_READ_BUFFER_SIZE - output_buffer_pos);

        if (bytes_read > 0) {
            printk("Bytes read: %u\n", bytes_read);
            output_buffer_pos += bytes_read;

            // Debug output
            // printk("Bytes read: %u, output buffer pos: %u\n", bytes_read, output_buffer_pos);

            // If the message ends in a newline, null-terminate the buffer
            if (tcp_buffer[output_buffer_pos - 1] == '\n') {
                tcp_buffer[output_buffer_pos - 1] = '\0';

                // Print received message to UART
                printk("\nPeer %u: %s\n", peer_rcp_addr, tcp_buffer);
                output_buffer_pos = 0;
            }
        }
    }

    // Close connection
    printk("Closing TCP connection...\n");
    tcp_close(&peer);

    // Final message
    printk("\nChat session ended.\n");

    // Print final statistics
    print_tcp_stats(&peer);

    // Print NRF statistics
    nrf_stat_print(nrf, "NRF stats");
}

void notmain(void) {
    // Initialize memory allocator
    uint32_t MB = 1024 * 1024;
    uint32_t start_addr = 3 * MB;
    uint32_t heap_size = 64 * MB;
    kmalloc_init_set_start((void *)start_addr, heap_size);

    // Run the chat application
    run_tcp_chat();

    printk("\nTCP CHAT APPLICATION: EXITED\n");
}