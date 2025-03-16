#include <stdbool.h>
#include <stdio.h>
#include <string.h>

#include "rcp-datagram.h"

// Test RCP header flag operations
static void test_rcp_flags(void) {
    printk("--------------------------------\n");
    printk("Testing RCP header flags...\n");

    // Create a header with no flags set
    rcp_header_t header = {0};

    // Test setting flags
    rcp_set_flag(&header, RCP_FLAG_SYN);
    assert(rcp_has_flag(&header, RCP_FLAG_SYN));
    assert(!rcp_has_flag(&header, RCP_FLAG_ACK));
    assert(!rcp_has_flag(&header, RCP_FLAG_FIN));
    printk("SYN flag set and verified\n");

    rcp_set_flag(&header, RCP_FLAG_ACK);
    assert(rcp_has_flag(&header, RCP_FLAG_SYN));
    assert(rcp_has_flag(&header, RCP_FLAG_ACK));
    assert(!rcp_has_flag(&header, RCP_FLAG_FIN));
    printk("ACK flag set and verified\n");

    rcp_set_flag(&header, RCP_FLAG_FIN);
    assert(rcp_has_flag(&header, RCP_FLAG_SYN));
    assert(rcp_has_flag(&header, RCP_FLAG_ACK));
    assert(rcp_has_flag(&header, RCP_FLAG_FIN));
    printk("FIN flag set and verified\n");

    // Test clearing flags
    rcp_clear_flag(&header, RCP_FLAG_SYN);
    assert(!rcp_has_flag(&header, RCP_FLAG_SYN));
    assert(rcp_has_flag(&header, RCP_FLAG_ACK));
    assert(rcp_has_flag(&header, RCP_FLAG_FIN));
    printk("SYN flag cleared and verified\n");

    printk("RCP flag operations passed!\n");
    printk("--------------------------------\n");
}

// Test RCP checksum operations
static void test_rcp_checksum(void) {
    printk("--------------------------------\n");
    printk("Testing RCP checksum...\n");

    // Create a datagram with some data
    rcp_datagram_t datagram = rcp_datagram_init();
    datagram.header.src = 1;
    datagram.header.dst = 2;
    datagram.header.seqno = 1000;
    datagram.header.ackno = 2000;
    datagram.header.window = 1024;
    rcp_set_flag(&datagram.header, RCP_FLAG_ACK);

    // Set some payload data
    const char *test_payload = "Test payload data";
    rcp_datagram_set_payload(&datagram, (uint8_t *)test_payload, strlen(test_payload));

    // Compute checksum
    uint16_t original_checksum = datagram.header.cksum;
    rcp_datagram_compute_checksum(&datagram);
    assert(datagram.header.cksum != original_checksum);
    printk("Checksum computed: %x\n", datagram.header.cksum);

    // Verify checksum
    assert(rcp_datagram_verify_checksum(&datagram));
    printk("Checksum verified successfully\n");

    // Modify the payload and verify checksum fails
    datagram.payload[0] = 'X';
    assert(!rcp_datagram_verify_checksum(&datagram));
    printk("Modified payload checksum verification failed as expected\n");

    // Recompute checksum with modified payload
    rcp_datagram_compute_checksum(&datagram);
    assert(rcp_datagram_verify_checksum(&datagram));
    printk("Recomputed checksum verified successfully\n");

    printk("RCP checksum operations passed!\n");
    printk("--------------------------------\n");
}

// Test RCP datagram serialization and parsing
static void test_rcp_serialization(void) {
    printk("--------------------------------\n");
    printk("Testing RCP serialization and parsing...\n");

    // Create a datagram with some data
    rcp_datagram_t datagram = rcp_datagram_init();
    datagram.header.src = 1;
    datagram.header.dst = 2;
    datagram.header.seqno = 1000;
    datagram.header.ackno = 2000;
    datagram.header.window = 1024;
    datagram.header.flags = 0;
    rcp_set_flag(&datagram.header, RCP_FLAG_ACK);
    rcp_set_flag(&datagram.header, RCP_FLAG_SYN);

    // Set some payload data
    const char *test_payload = "Serialization test payload";
    rcp_datagram_set_payload(&datagram, (uint8_t *)test_payload, strlen(test_payload));

    // Compute checksum
    rcp_datagram_compute_checksum(&datagram);

    // Serialize the datagram
    uint8_t buffer[RCP_TOTAL_SIZE];
    uint16_t length = rcp_datagram_serialize(&datagram, buffer, RCP_TOTAL_SIZE);
    assert(length > 0);
    printk("Datagram serialized, length: %u bytes\n", length);

    // Parse the serialized datagram
    rcp_datagram_t parsed_datagram = rcp_datagram_init();
    bool parse_success = rcp_datagram_parse(&parsed_datagram, buffer, length);
    assert(parse_success);
    printk("Datagram parsed successfully\n");

    // Verify the parsed datagram matches the original
    assert(parsed_datagram.header.src == datagram.header.src);
    assert(parsed_datagram.header.dst == datagram.header.dst);
    assert(parsed_datagram.header.seqno == datagram.header.seqno);
    assert(parsed_datagram.header.ackno == datagram.header.ackno);
    assert(parsed_datagram.header.window == datagram.header.window);
    assert(parsed_datagram.header.flags == datagram.header.flags);
    assert(parsed_datagram.header.cksum == datagram.header.cksum);
    assert(parsed_datagram.payload_len == datagram.payload_len);
    assert(memcmp(parsed_datagram.payload, datagram.payload, datagram.payload_len) == 0);
    printk("Parsed datagram fields match original\n");

    // Verify the checksum of the parsed datagram
    assert(rcp_datagram_verify_checksum(&parsed_datagram));
    printk("Parsed datagram checksum verified\n");

    printk("RCP serialization and parsing passed!\n");
    printk("--------------------------------\n");
}

void notmain(void) {
    printk("Starting RCP implementation tests...\n\n");
    kmalloc_init(64);
    printk("Memory initialized\n");

    printk("RCP_HEADER_LENGTH: %u\n", RCP_HEADER_LENGTH);
    printk("sizeof(rcp_header_t): %u\n", sizeof(rcp_header_t));

    printk("RCP_DATAGRAM_LENGTH: %u\n", RCP_TOTAL_SIZE);
    printk("sizeof(rcp_datagram_t): %u\n", sizeof(rcp_datagram_t));

    test_rcp_flags();
    test_rcp_checksum();
    test_rcp_serialization();

    printk("\nAll RCP tests passed!\n");
}