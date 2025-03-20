// test that sw uart works.
#include "rpi.h"
#include "sw-uart.h"

void notmain(void) {
    output("Please type some characters (5 sec timeout):\n");
    hw_uart_disable();

    // use pin 14 for tx, 15 for rx
    sw_uart_t u = sw_uart_init(14, 15, 115200);

    // print in the most basic way.
    while (1) {
        char buf[1280];
        int i = 0;
        while (1) {
            // char c = sw_uart_get8(&u);
            // // Print the character
            // sw_uart_put8(&u, c);
            // sw_uart_put8(&u, ':');
            // sw_uart_put8(&u, ' ');

            // // Print each bit from MSB to LSB
            // for(int i = 7; i >= 0; i--) {
            //     sw_uart_put8(&u, ((c >> i) & 1) ? '1' : '0');
            // }
            // sw_uart_put8(&u, '\n');

            // blocking get8 with a 1000 second timeout
            char c = sw_uart_get8_timeout(&u, 1000 * 1000 * 1000);
            buf[i++] = c;
            if (c == '\n') {
                buf[i] = '\0';
                break;
            }
        }

        if (strcmp(buf, "quit\n") == 0) {
            break;
        }

        sw_uart_printk(&u, "You typed: %s\n", buf);
    }

    // reset to using the hardware uart.
    uart_init();

    trace("if you see `hello` above, sw uart worked!\n");
}
