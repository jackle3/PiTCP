#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "libunix.h"

// Generate a file with random content of specified size
int main(int argc, char *argv[]) {
    if (argc != 2)
        panic("Usage: %s <size_in_bytes>\n", argv[0]);

    // Parse the size argument
    unsigned long size = strtoul(argv[1], NULL, 10);
    if (size == 0)
        panic("Invalid size specified\n");

    // Create a buffer for generating content
    // Use a reasonable chunk size to avoid excessive memory usage
    const unsigned chunk_size = 4096;
    unsigned char *buffer = malloc(chunk_size);
    if (!buffer)
        panic("Failed to allocate memory\n");

    // Open a temporary file for writing
    char filename[256];
    snprintf(filename, sizeof(filename), "generated-%lu.bin", size);
    FILE *fp = fopen(filename, "wb");
    if (!fp)
        panic("Failed to open file for writing: %s\n", filename);

    // Seed the random number generator
    srand(time(NULL));

    // Write data in chunks
    unsigned long remaining = size;
    while (remaining > 0) {
        unsigned current_chunk = (remaining > chunk_size) ? chunk_size : remaining;

        // Fill the buffer with random data
        for (unsigned i = 0; i < current_chunk; i++) buffer[i] = rand() % 256;

        // Write the chunk to the file
        if (fwrite(buffer, 1, current_chunk, fp) != current_chunk) {
            fclose(fp);
            free(buffer);
            panic("Failed to write to file\n");
        }

        remaining -= current_chunk;
    }

    // Clean up
    fclose(fp);
    free(buffer);

    printf("Generated file '%s' of size %lu bytes\n", filename, size);
    return 0;
}
