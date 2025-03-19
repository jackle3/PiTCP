#pragma once

#include "nrf.h"

// router uses nrf_addr_router
// user 1 uses nrf_addr_1
// user 2 uses nrf_addr_2

/**
 * Router's rtable: maps from RCP address to NRF address
 * - RCP address 0 is the router itself
 * - RCP address 1 should route to the first user (receiver)
 * - RCP address 2 should route to the second user (receiver))
 */
static uint32_t router_rtable[256] = {
    [0] = 0,               /* Goes nowhere */
    [1] = nrf_user_1_addr, /* Route to first server */
    [2] = nrf_user_2_addr  /* Route to second server */
};

/**
 * First user's rtable: maps from RCP address to NRF address
 * - RCP address 0 should route to the router's server (receiver)
 * - RCP address 1 is the user itself
 * - RCP address 2 should route to the router's server (receiver)
 */
static uint32_t user1_rtable[256] = {
    [0] = nrf_router_server_addr, /* Route to router */
    [1] = 0,                      /* Goes nowhere */
    // [2] = nrf_router_server_addr  /* Route to router */
    [2] = nrf_user_2_addr /* Route directly to user 2 */
};

/**
 * Second user's rtable: maps from RCP address to NRF address
 * - RCP address 0 should route to the router's server (receiver)
 * - RCP address 1 should route to the router's server (receiver)
 * - RCP address 2 is the user itself
 */
static uint32_t user2_rtable[256] = {
    [0] = nrf_router_server_addr, /* Route to router */
    // [1] = nrf_router_server_addr, /* Route to router */
    [1] = nrf_user_1_addr, /* Route directly to user 1 */
    [2] = 0                /* Goes nowhere */
};

/**
 * Routing table mapping: maps from RCP address to the corresponding routing table
 * - RCP address 0 maps to router_rtable
 * - RCP address 1 maps to user1_rtable
 * - RCP address 2 maps to user2_rtable
 */
static uint32_t *rtable_map[256] = {
    [0] = router_rtable,
    [1] = user1_rtable,
    [2] = user2_rtable,
};

static uint32_t rcp_to_nrf[256] = {
    [0] = nrf_router_server_addr,
    [1] = nrf_user_1_addr,
    [2] = nrf_user_2_addr,
};