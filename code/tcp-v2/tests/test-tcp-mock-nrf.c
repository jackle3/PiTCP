// Include types first so nrf_t is defined
#include "nrf.h"
#include "types.h"

// Define our mock functions
static int mock_nrf_send_noack(nrf_t *nic, uint32_t txaddr, const void *msg, unsigned nbytes);
static int mock_nrf_read_exact_timeout(nrf_t *nic, void *msg, unsigned nbytes, unsigned timeout_us);

// Override the actual functions with our mocks
#undef nrf_send_noack
#define nrf_send_noack mock_nrf_send_noack
#undef nrf_read_exact_timeout
#define nrf_read_exact_timeout mock_nrf_read_exact_timeout

// Include the rest of the headers
#include "bytestream.h"
#include "rcp-datagram.h"
#include "tcp.h"

// Test parameters
#define TEST_ITERATIONS 1000
#define DELAY_MS 5

// Circular buffer for packet exchange between peers
#define MAX_PACKETS 32
typedef struct {
    uint8_t data[MAX_PACKETS][RCP_TOTAL_SIZE];
    size_t lengths[MAX_PACKETS];
    uint32_t addrs[MAX_PACKETS];
    int head;
    int tail;
    int count;
} packet_buffer_t;

// Global packet buffers for our mock network
static packet_buffer_t client_to_server;
static packet_buffer_t server_to_client;

// Track flags for verifying connection stages
static bool syn_seen = false;
static bool syn_ack_seen = false;
static bool ack_seen = false;
static bool client_fin_seen = false;     // Client sent FIN
static bool server_ack_for_fin = false;  // Server ACKed client's FIN
static bool server_fin_seen = false;     // Server sent FIN
static bool client_ack_for_fin = false;  // Client ACKed server's FIN

// Mock NRF structure
typedef struct mock_nrf {
    int id;  // 1 = client, 2 = server
} mock_nrf_t;

// Initialize packet buffer
static void packet_buffer_init(packet_buffer_t *buffer) {
    memset(buffer, 0, sizeof(packet_buffer_t));
    buffer->head = 0;
    buffer->tail = 0;
    buffer->count = 0;
}

// Add packet to buffer
static bool packet_buffer_put(packet_buffer_t *buffer, const void *data, size_t length,
                              uint32_t addr) {
    if (buffer->count >= MAX_PACKETS) {
        return false;  // Buffer full
    }

    memcpy(buffer->data[buffer->tail], data, length);
    buffer->lengths[buffer->tail] = length;
    buffer->addrs[buffer->tail] = addr;

    buffer->tail = (buffer->tail + 1) % MAX_PACKETS;
    buffer->count++;
    return true;
}

// Get packet from buffer
static int packet_buffer_get(packet_buffer_t *buffer, void *data, size_t max_length,
                             uint32_t addr) {
    if (buffer->count == 0) {
        return 0;  // Buffer empty
    }

    // Just get the packet at the head
    size_t length = buffer->lengths[buffer->head];
    if (length > max_length) {
        length = max_length;
    }

    memcpy(data, buffer->data[buffer->head], length);

    // Remove the packet
    buffer->head = (buffer->head + 1) % MAX_PACKETS;
    buffer->count--;

    return length;
}

// Initialize mock NRF
static mock_nrf_t *mock_nrf_init(int id) {
    mock_nrf_t *nrf = kmalloc(sizeof(mock_nrf_t));
    nrf->id = id;
    return nrf;
}

// Mock implementation of nrf_send_noack with improved connection termination tracking
static int mock_nrf_send_noack(nrf_t *nic, uint32_t txaddr, const void *msg, unsigned nbytes) {
    mock_nrf_t *mock = (mock_nrf_t *)nic;

    // Detect control flags for debugging
    if (nbytes >= RCP_HEADER_LENGTH) {
        rcp_datagram_t datagram = rcp_datagram_init();
        if (rcp_datagram_parse(&datagram, msg, nbytes) > 0) {
            bool is_syn = rcp_has_flag(&datagram.header, RCP_FLAG_SYN);
            bool is_ack = rcp_has_flag(&datagram.header, RCP_FLAG_ACK);
            bool is_fin = rcp_has_flag(&datagram.header, RCP_FLAG_FIN);

            printk("Sending datagram to %x: SYN: %d, ACK: %d, FIN: %d", txaddr, is_syn, is_ack,
                   is_fin);
            if (is_ack) {
                printk(", ackno: %u", datagram.header.ackno);
            }
            printk("\n");

            // Track connection establishment
            if (is_syn && !is_ack) {
                printk("SYN sent from %d\n", mock->id);
                syn_seen = true;
            } else if (is_syn && is_ack) {
                printk("SYN-ACK sent from %d\n", mock->id);
                syn_ack_seen = true;
            } else if (is_ack && syn_ack_seen && !ack_seen) {
                printk("Initial ACK sent from %d\n", mock->id);
                ack_seen = true;
            }
            // Track connection termination
            else if (is_fin) {
                if (mock->id == 1) {
                    printk("FIN sent from client\n");
                    client_fin_seen = true;
                } else {
                    printk("FIN sent from server\n");
                    server_fin_seen = true;
                }
            }
            // Track ACKs for FINs during termination
            else if (is_ack) {
                // Check if this is a server ACK for client FIN
                if (mock->id == 2 && client_fin_seen && !server_ack_for_fin) {
                    // This heuristic assumes the ACK is for the FIN if it comes after
                    // client_fin_seen A more precise check would compare sequence numbers
                    printk("ACK from server for client's FIN\n");
                    server_ack_for_fin = true;
                }
                // Check if this is a client ACK for server FIN
                else if (mock->id == 1 && server_fin_seen && !client_ack_for_fin) {
                    printk("ACK from client for server's FIN\n");
                    client_ack_for_fin = true;
                }
            }
        }
    }

    // Route packet to appropriate buffer
    if (mock->id == 1) {
        // Client sending to server
        packet_buffer_put(&client_to_server, msg, nbytes, txaddr);
    } else {
        // Server sending to client
        packet_buffer_put(&server_to_client, msg, nbytes, txaddr);
    }

    return nbytes;
}

// Mock implementation of nrf_read_exact_timeout
static int mock_nrf_read_exact_timeout(nrf_t *nic, void *msg, unsigned nbytes,
                                       unsigned timeout_us) {
    mock_nrf_t *mock = (mock_nrf_t *)nic;
    int received = 0;

    // Read from appropriate buffer
    if (mock->id == 1) {
        // Client reading from server
        received = packet_buffer_get(&server_to_client, msg, nbytes, 0);
    } else {
        // Server reading from client
        received = packet_buffer_get(&client_to_server, msg, nbytes, 0);
    }

    return received;
}

// Helper function to run both peers through several ticks
static void run_tcp_ticks(tcp_peer_t *client, tcp_peer_t *server, int count) {
    for (int i = 0; i < count; i++) {
        tcp_tick(client);
        tcp_tick(server);
        delay_ms(DELAY_MS);  // Simulate network latency
    }
}

// Helper to print TCP state name
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

// Test function for TCP implementation with complete connection lifecycle
void test_tcp_handshake_and_data_transfer() {
    printk("=== TCP Handshake and Data Transfer Test ===\n");

    // Reset flags
    syn_seen = false;
    syn_ack_seen = false;
    ack_seen = false;
    client_fin_seen = false;
    server_ack_for_fin = false;
    server_fin_seen = false;
    client_ack_for_fin = false;

    // Initialize packet buffers
    packet_buffer_init(&client_to_server);
    packet_buffer_init(&server_to_client);

    // Initialize NRFs
    mock_nrf_t *client_nrf = mock_nrf_init(1);
    mock_nrf_t *server_nrf = mock_nrf_init(2);

    printk("Initializing TCP peers...\n");

    // Initialize TCP peers
    // For client, we pass false as the last parameter to indicate it's a client
    tcp_peer_t client = tcp_peer_init((nrf_t *)client_nrf, (nrf_t *)client_nrf, 1, 2, false);

    // For server, we pass true as the last parameter to indicate it's a server
    tcp_peer_t server = tcp_peer_init((nrf_t *)server_nrf, (nrf_t *)server_nrf, 2, 1, true);

    printk("TCP peers initialized\n");
    printk("Client state: %s, Server state: %s\n", tcp_state_name(client.state),
           tcp_state_name(server.state));

    // Step 1: Initiate connection from client to server
    printk("\nStep 1: Initiating connection (SYN, SYN-ACK, ACK handshake)\n");

    // Actively initiate connection from client
    tcp_connect(&client);

    // Run TCP ticks to complete handshake
    int handshake_iterations = 0;
    while ((!syn_seen || !syn_ack_seen || !ack_seen) && handshake_iterations < TEST_ITERATIONS) {
        run_tcp_ticks(&client, &server, 1);
        handshake_iterations++;

        if (handshake_iterations % 10 == 0) {
            printk("Handshake progress: SYN: %d, SYN-ACK: %d, ACK: %d (iterations: %d)\n", syn_seen,
                   syn_ack_seen, ack_seen, handshake_iterations);
            printk("Client state: %s, Server state: %s\n", tcp_state_name(client.state),
                   tcp_state_name(server.state));
        }
    }

    // Verify handshake completed
    assert(syn_seen && "Client did not send SYN");
    assert(syn_ack_seen && "Server did not send SYN-ACK");
    assert(ack_seen && "Client did not send final ACK");
    assert(tcp_is_established(&client) && "Client connection not established");
    assert(tcp_is_established(&server) && "Server connection not established");

    printk("Connection established successfully after %d iterations\n", handshake_iterations);
    printk("Client state: %s, Server state: %s\n", tcp_state_name(client.state),
           tcp_state_name(server.state));

    // Step 2: Send data from client to server
    printk("\nStep 2: Sending data from client to server\n");

    // Print out connection state information
    printk("Client sender state: next_seqno: %u, window_size: %u\n", client.sender.next_seqno,
           client.sender.window_size);
    printk("Client receiver state: syn_received: %d, next_seqno: %u, window_size: %u\n",
           client.receiver.syn_received, client.receiver.next_seqno, client.receiver.window_size);

    printk("Server sender state: next_seqno: %u, window_size: %u\n", server.sender.next_seqno,
           server.sender.window_size);
    printk("Server receiver state: syn_received: %d, next_seqno: %u, window_size: %u\n",
           server.receiver.syn_received, server.receiver.next_seqno, server.receiver.window_size);

    const char *client_message = "Hello from client!";
    size_t client_message_len = strlen(client_message);

    // Write data to client
    size_t written = tcp_write(&client, (uint8_t *)client_message, client_message_len);
    assert(written == client_message_len);
    printk("Client wrote %u bytes\n", written);

    // Run TCP ticks to transfer data
    int data_transfer_iterations = 0;
    bool client_data_received = false;

    while (!client_data_received && data_transfer_iterations < TEST_ITERATIONS) {
        run_tcp_ticks(&client, &server, 1);
        data_transfer_iterations++;

        // Check if server has received data
        if (tcp_has_data(&server) &&
            bs_bytes_available(&server.receiver.writer) >= client_message_len) {
            client_data_received = true;
        }

        if (data_transfer_iterations % 10 == 0) {
            printk("Client->Server data transfer progress: %u/%u bytes (iterations: %d)\n",
                   tcp_has_data(&server) ? bs_bytes_available(&server.receiver.writer) : 0,
                   client_message_len, data_transfer_iterations);
        }
    }

    // Verify data was received
    assert(client_data_received && "Server did not receive client data");

    // Read and verify data on server
    uint8_t server_buffer[256];
    size_t read = tcp_read(&server, server_buffer, sizeof(server_buffer));
    server_buffer[read] = '\0';

    assert(read == client_message_len);
    assert(memcmp(server_buffer, client_message, client_message_len) == 0);
    printk("Server received %u bytes: '%s'\n", read, server_buffer);

    // Step 3: Send data from server to client
    printk("\nStep 3: Sending data from server to client\n");

    const char *server_message = "Response from server!";
    size_t server_message_len = strlen(server_message);

    // Write data to server
    written = tcp_write(&server, (uint8_t *)server_message, server_message_len);
    assert(written == server_message_len);
    printk("Server wrote %u bytes\n", written);

    // Run TCP ticks to transfer data
    data_transfer_iterations = 0;
    bool server_data_received = false;

    while (!server_data_received && data_transfer_iterations < TEST_ITERATIONS) {
        run_tcp_ticks(&client, &server, 1);
        data_transfer_iterations++;

        // Check if client has received data
        if (tcp_has_data(&client) &&
            bs_bytes_available(&client.receiver.writer) >= server_message_len) {
            server_data_received = true;
        }

        if (data_transfer_iterations % 10 == 0) {
            printk("Server->Client data transfer progress: %u/%u bytes (iterations: %d)\n",
                   tcp_has_data(&client) ? bs_bytes_available(&client.receiver.writer) : 0,
                   server_message_len, data_transfer_iterations);
        }
    }

    // Verify data was received
    assert(server_data_received && "Client did not receive server data");

    // Read and verify data on client
    uint8_t client_buffer[256];
    read = tcp_read(&client, client_buffer, sizeof(client_buffer));
    client_buffer[read] = '\0';

    assert(read == server_message_len);
    assert(memcmp(client_buffer, server_message, server_message_len) == 0);
    printk("Client received %u bytes: '%s'\n", read, client_buffer);

    // Step 4: Connection termination - complete four-way handshake
    printk("\nStep 4: Closing connection (four-way handshake)\n");

    // Reset FIN tracking
    client_fin_seen = false;
    server_ack_for_fin = false;
    server_fin_seen = false;
    client_ack_for_fin = false;

    // First, client initiates close
    printk("1. Client initiating connection close\n");
    tcp_close(&client);

    // Run some ticks to let the client FIN propagate and get ACKed
    int client_close_iterations = 0;
    while ((!client_fin_seen || !server_ack_for_fin) && client_close_iterations < TEST_ITERATIONS) {
        run_tcp_ticks(&client, &server, 1);
        client_close_iterations++;

        if (client_close_iterations % 5 == 0) {
            printk("Client close progress: Client FIN: %d, Server ACK: %d (iterations: %d)\n",
                   client_fin_seen, server_ack_for_fin, client_close_iterations);
            printk("Client state: %s, Server state: %s\n", tcp_state_name(client.state),
                   tcp_state_name(server.state));
        }
    }

    // Verify step 1 and 2 of closing handshake
    assert(client_fin_seen && "Client did not send FIN");
    assert(server_ack_for_fin && "Server did not ACK client's FIN");

    // Server should be in CLOSE_WAIT state now
    printk("Client FIN sent and ACKed. Client state: %s, Server state: %s\n",
           tcp_state_name(client.state), tcp_state_name(server.state));

    // Server now initiates its own close
    printk("2. Server closing connection\n");
    tcp_close(&server);

    // Run ticks to complete the connection termination
    int server_close_iterations = 0;
    while ((!server_fin_seen || !client_ack_for_fin) && server_close_iterations < TEST_ITERATIONS) {
        run_tcp_ticks(&client, &server, 1);
        server_close_iterations++;

        if (server_close_iterations % 5 == 0) {
            printk("Server close progress: Server FIN: %d, Client ACK: %d (iterations: %d)\n",
                   server_fin_seen, client_ack_for_fin, server_close_iterations);
            printk("Client state: %s, Server state: %s\n", tcp_state_name(client.state),
                   tcp_state_name(server.state));
        }
    }

    // Verify step 3 and 4 of closing handshake
    assert(server_fin_seen && "Server did not send FIN");
    assert(client_ack_for_fin && "Client did not ACK server's FIN");

    // Let the connection terminate fully (TIME_WAIT -> CLOSED)
    int termination_iterations = 0;
    bool fully_closed = false;

    while (!fully_closed && termination_iterations < TEST_ITERATIONS) {
        run_tcp_ticks(&client, &server, 2);  // More ticks per iteration
        termination_iterations++;

        // Check for full termination
        if (!tcp_is_active(&client) && !tcp_is_active(&server)) {
            fully_closed = true;
        }

        if (termination_iterations % 20 == 0) {
            printk("Termination progress (iterations: %d)\n", termination_iterations);
            uint32_t now = timer_get_usec();
            uint32_t expire_time = client.time_of_last_receipt + 2 * client.sender.initial_RTO_us;
            printk("  [TCP] TIME_WAIT: current time %u, last receipt %u, RTO %u, expire_time %u\n",
                   now, client.time_of_last_receipt, client.sender.initial_RTO_us, expire_time);
            printk("Client state: %s, Server state: %s\n", tcp_state_name(client.state),
                   tcp_state_name(server.state));
            printk("Client active: %d, Server active: %d\n", tcp_is_active(&client),
                   tcp_is_active(&server));
        }
    }

    // Final verification
    assert(!tcp_is_active(&client) && "Client connection still active");
    assert(!tcp_is_active(&server) && "Server connection still active");
    assert(tcp_receive_closed(&server) && "Server receiving side not closed");
    assert(tcp_receive_closed(&client) && "Client receiving side not closed");

    printk("Connection terminated successfully! Four-way handshake completed.\n");
    printk("Final states - Client: %s, Server: %s\n", tcp_state_name(client.state),
           tcp_state_name(server.state));
    printk("=== Test completed successfully! ===\n");
}

void notmain(void) {
    kmalloc_init(64);
    test_tcp_handshake_and_data_transfer();
}