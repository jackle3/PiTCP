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
#define TEST_ITERATIONS 100
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

// Track flags for verifying handshake
static bool syn_seen = false;
static bool syn_ack_seen = false;
static bool ack_seen = false;
static bool fin_seen = false;
static bool fin_ack_seen = false;

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

// Mock implementation of nrf_send_noack
static int mock_nrf_send_noack(nrf_t *nic, uint32_t txaddr, const void *msg, unsigned nbytes) {
    mock_nrf_t *mock = (mock_nrf_t *)nic;

    // Detect control flags for debugging
    if (nbytes >= RCP_HEADER_LENGTH) {
        rcp_datagram_t datagram = rcp_datagram_init();
        if (rcp_datagram_parse(&datagram, msg, nbytes) > 0) {
            bool is_syn = rcp_has_flag(&datagram.header, RCP_FLAG_SYN);
            bool is_ack = rcp_has_flag(&datagram.header, RCP_FLAG_ACK);
            bool is_fin = rcp_has_flag(&datagram.header, RCP_FLAG_FIN);
            printk("Sending datagram to %x: SYN: %d, ACK: %d, FIN: %d\n", txaddr, is_syn, is_ack,
                   is_fin);

            if (is_syn && !is_ack) {
                printk("SYN sent from %d\n", mock->id);
                syn_seen = true;
            } else if (is_syn && is_ack) {
                printk("SYN-ACK sent from %d\n", mock->id);
                syn_ack_seen = true;
            } else if (is_ack && syn_ack_seen) {
                printk("Initial ACK sent from %d\n", mock->id);
                ack_seen = true;
            } else if (is_fin) {
                printk("FIN sent from %d\n", mock->id);
                fin_seen = true;
            } else if (is_ack && fin_seen && !fin_ack_seen) {
                printk("FIN-ACK sent from %d\n", mock->id);
                fin_ack_seen = true;
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

// Test function for TCP implementation
void test_tcp_handshake_and_data_transfer() {
    printk("=== TCP Handshake and Data Transfer Test ===\n");

    // Reset flags
    syn_seen = false;
    syn_ack_seen = false;
    ack_seen = false;
    fin_seen = false;
    fin_ack_seen = false;

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
        }
    }

    // Verify handshake completed
    assert(syn_seen && "Client did not send SYN");
    assert(syn_ack_seen && "Server did not send SYN-ACK");
    assert(ack_seen && "Client did not send final ACK");
    assert(tcp_is_established(&client) && "Client connection not established");
    assert(tcp_is_established(&server) && "Server connection not established");

    printk("Connection established successfully after %d iterations\n", handshake_iterations);

    // Step 2: Send data from client to server
    printk("\nStep 2: Sending data from client to server\n");

    // Print out data about the server (i.e. syn_received, next_seqno, window_size)
    printk("Client sender state: next_seqno: %u, window_size: %u\n", client.sender.next_seqno,
           client.sender.window_size);
    printk(
        "Client receiver state: syn_received: %d, next_seqno: %u, window_size: %u, total_size: "
        "%u\n",
        client.receiver.syn_received, client.receiver.next_seqno, client.receiver.window_size,
        client.receiver.total_size);

    printk("Server sender state: next_seqno: %u, window_size: %u\n", server.sender.next_seqno,
           server.sender.window_size);
    printk(
        "Server receiver state: syn_received: %d, next_seqno: %u, window_size: %u, total_size: "
        "%u\n",
        server.receiver.syn_received, server.receiver.next_seqno, server.receiver.window_size,
        server.receiver.total_size);

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
            printk("Client->Server data transfer progress: %d/%u bytes (iterations: %d)\n",
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
            printk("Server->Client data transfer progress: %d/%u bytes (iterations: %d)\n",
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

    // Step 4: Close connection
    printk("\nStep 4: Closing connection\n");

    // Reset FIN tracking
    fin_seen = false;
    fin_ack_seen = false;

    // Close the client connection
    tcp_close(&client);

    // Run TCP ticks to complete connection termination
    int termination_iterations = 0;
    bool connection_closed = false;

    while (!connection_closed && termination_iterations < TEST_ITERATIONS) {
        run_tcp_ticks(&client, &server, 1);
        termination_iterations++;

        // Check if connection is fully terminated
        if (fin_seen && fin_ack_seen && tcp_receive_closed(&server)) {
            connection_closed = true;
        }

        if (termination_iterations % 10 == 0) {
            printk("Connection termination progress: FIN: %d, FIN-ACK: %d (iterations: %d)\n",
                   fin_seen, fin_ack_seen, termination_iterations);
        }

        // For testing, force disable lingering after a certain time
        if (termination_iterations > 50) {
            client.linger_after_streams_finish = false;
            server.linger_after_streams_finish = false;
        }
    }

    // Verify connection was closed properly
    assert(fin_seen && "Client did not send FIN");
    assert(fin_ack_seen && "Server did not acknowledge FIN");
    assert(tcp_receive_closed(&server) && "Server did not close receiving side");

    printk("Connection terminated successfully after %d iterations\n", termination_iterations);
    printk("=== Test completed successfully! ===\n");
}

void notmain(void) {
    kmalloc_init(64);
    test_tcp_handshake_and_data_transfer();
}