# PiTCP

This is a full TCP implementation on the Raspberry Pi. It communicates over the nRF radio module using 32 byte RCP datagrams. RCP is a novel protocol that we proposed for this project -- it is an amalgamation of TCP and IP, distilled to essential components to fit in a 32 byte NRF packet while maximizing the payload.

The implementation includes several components:

- `tcp-v2/tcp-uart` - A UART-based interface to allow two users to chat with each other over our TCP implementation.
- `tcp-v2/tcp-router` - A router that can route RCP datagrams between users based on a pre-defined routing table.
- `tcp-v2/tcp-p2p-client` - A client that can send a file to a server.
- `tcp-v2/tcp-p2p-server` - A server that can receive a file from a client.
- `tcp-v2/tcp-loopback-file` - A program that tests the maximum possible throughput of the TCP implementation by sending a file in a loopback scenario (i.e. the client and server are on the same Pi).

## Setup

Add the following to your `.zshrc` or `.bashrc` file:

```
# CS140E Final Project Path
export CS140E_PITCP="path/to/your/repo"
```

If you don't know the path, run `sh get_export.sh` from the `./PiTCP` directory.

## Usage

- To run the UART program, run `make` inside `code/tcp-v2` and then run `my-install programs/tcp-uart.bin`.
- To run the router, run `make` inside `code/tcp-v2` and then run `my-install programs/tcp-router.bin`.
- To send a file from one peer to another:
  - The client should run `my-install programs/tcp-p2p-client.bin`.
  - The server should run `my-install programs/tcp-p2p-server.bin`.
- To test in a loopback scenario (i.e. maximum possible throughput), run `my-install tests/tcp-loopback-file.bin`.

## TCP Implementation Details

Our TCP implementation is built on top of a novel protocol called RCP (Raspberry-Pi Communication Protocol), which is designed to fit within the 32-byte size constraint of nRF radio packets while maintaining essential TCP/IP functionality.

### RCP Protocol

RCP (Reliable Communication Protocol) is a custom protocol that combines TCP and IP functionality:

- **Packet Format**: 32-byte fixed size packets
  - 9-byte header containing:
    - Checksum (1 byte)
    - Combined source/destination addresses (1 byte)
    - Sequence number (2 bytes)
    - Flags and payload length (1 byte)
    - Acknowledgment number (2 bytes)
    - Window size (2 bytes)
  - Up to 23 bytes of payload data

- **Features**:
  - Reliable delivery through sequence numbers and acknowledgments
  - Flow control using sliding window
  - Connection management with SYN/FIN flags
  - Checksum for error detection
  - Routing support through 4-bit addresses

### TCP State Machine

The implementation follows the standard TCP state machine:

1. **Connection Establishment (3-way handshake)**:
   - Client sends SYN
   - Server responds with SYN-ACK
   - Client acknowledges with ACK

2. **Data Transfer**:
   - Reliable delivery using sequence numbers and acknowledgments
   - Flow control with sliding window
   - Fast retransmit after 3 duplicate ACKs
   - Out-of-order packet handling with reassembly

3. **Connection Termination**:
   - Either peer can initiate with FIN
   - Full four-way handshake
   - TIME_WAIT state (2 seconds) to ensure reliable closure

### Key Features

1. **Reliability**:
   - Sequence numbers for ordering
   - Acknowledgments for reliability
   - Retransmission queue for unacknowledged segments
   - Configurable retransmission timeout (RTO)

2. **Flow Control**:
   - Sliding window protocol
   - Dynamic window sizing
   - Maximum window size of 128 bytes
   - Bytestream abstraction for data transfer

3. **Performance Optimizations**:
   - Fast retransmit on triple duplicate ACKs
   - Efficient segment reassembly
   - Piggyback acknowledgments when possible
   - Configurable initial RTO

4. **Statistics Tracking**:
   - Segments sent/received (total, data, SYN, FIN, ACK)
   - Retransmission statistics
   - Throughput measurements
   - Connection state monitoring

### Architecture

The implementation is modular with several key components:

1. **TCP Peer**: Main connection endpoint managing:
   - Connection state
   - Segment processing
   - Retransmission handling
   - Statistics collection

2. **Sender**: Handles outbound data:
   - Sequence number management
   - Window size tracking
   - Segment creation
   - Retransmission decisions

3. **Receiver**: Manages inbound data:
   - In-order delivery
   - Segment reassembly
   - Window advertisement
   - ACK generation

4. **Router**: Provides packet routing:
   - Address-based forwarding
   - Route table management
   - Multi-hop support

### Usage Examples

The implementation includes several example applications:

1. **TCP UART Chat** (`tcp-uart`):
   - Interactive chat between two peers
   - Real-time message exchange
   - Connection statistics display

2. **TCP File Transfer** (`tcp-p2p-client/server`):
   - Reliable file transfer between peers
   - Progress monitoring
   - Data integrity verification

3. **TCP Router** (`tcp-router`):
   - Multi-peer message routing
   - Address-based forwarding
   - Connection multiplexing

4. **TCP Loopback** (`tcp-loopback-file`):
   - Performance testing
   - Maximum throughput measurement
   - Connection reliability verification
