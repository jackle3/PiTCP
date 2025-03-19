#include "nrf-test.h"
#include "router.h"
#include "tcp.h"

#define ROUTER_RCP_ADDR 0

// busy loop, and check nrf_read_exact_timeout, if we have a packet then parse the packet
// as a datagram and route it to correct destination based on the destination address
void route_messages(nrf_t *server, nrf_t *client) {
    uint8_t buffer[RCP_TOTAL_SIZE];

    while (1) {
        int bytes_read = nrf_read_exact_timeout(server, buffer, RCP_TOTAL_SIZE, 1000);
        if (bytes_read > 0) {
            // Parse the datagram
            rcp_datagram_t dgram = rcp_datagram_init();
            if (!rcp_datagram_parse(&dgram, buffer, bytes_read)) {
                printk("[ROUTER] Failed to parse RCP datagram\n");
                continue;
            }

            // Route it to the correct destination based on the destination address
            uint8_t src_rcp = rcp_get_src_addr(&dgram.header);
            uint8_t dst_rcp = rcp_get_dst_addr(&dgram.header);

            // Use the router's own routing table to look up the next hop
            uint32_t next_hop_nrf = rtable_map[ROUTER_RCP_ADDR][dst_rcp];

            nrf_send_noack(client, next_hop_nrf, buffer, bytes_read);
            printk("[ROUTER] Route message from %x to %x (nrf: %x)\n", src_rcp, dst_rcp,
                   next_hop_nrf);
        }
    }
}

void notmain(void) {
    kmalloc_init(64);
    uart_init();

    printk("[ROUTER] Configuring no-ack server=[%x] with %d nbyte msgs\n", router_server_addr,
           RCP_TOTAL_SIZE);
    nrf_t *s = router_mk_noack(router_server_addr, RCP_TOTAL_SIZE);
    // nrf_dump("unreliable server config:\n", s);

    printk("[ROUTER] Configuring no-ack client=[%x] with %d nbyte msg\n", router_client_addr,
           RCP_TOTAL_SIZE);
    nrf_t *c = client_mk_noack(router_client_addr, RCP_TOTAL_SIZE);
    // nrf_dump("unreliable client config:\n", c);

    // Check compatibility
    if (!nrf_compat(c, s))
        panic("[ROUTER] did not configure correctly: not compatible\n");

    // Reset stats
    nrf_stat_start(s);
    nrf_stat_start(c);

    // trace("Starting test...\n");

    route_messages(s, c);

    // Print stats
    nrf_stat_print(s, "server: done with test");
    nrf_stat_print(c, "client: done with test");
}