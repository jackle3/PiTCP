#include "libunix.h"

int main(int argc, char *argv[]) {
    if(argc != 2)
        panic("expected argc=2, have %d\n", argc);

    // Canonicalize the name for variable use
    char var[1024], *name = argv[1];
    unsigned i;
    for(i = 0; name[i]; i++) {
        if(name[i] == '.')
            break;
        else if(name[i] == '-')
            var[i] = '_';
        else
            var[i] = name[i];
    }
    var[i] = 0;
        
    // Read the binary file
    unsigned nbytes = 0;
    uint8_t *code = read_file(&nbytes, argv[1]);
    
    if(!code || nbytes == 0)
        panic("Failed to read file or file is empty\n");

    // Generate the C array declaration
    printf("// Binary data array generated from: %s\n", argv[1]);
    printf("static const uint8_t binary_data[] = {\n");
    
    // Print the bytes in rows of 8
    for(unsigned i = 0; i < nbytes; i++) {
        if(i % 8 == 0)
            printf("    ");
        
        // Print each byte with proper hex formatting (0x and leading zero if needed)
        printf("0x%02x", code[i]);
        
        // Add comma if not the last byte
        if(i < nbytes - 1)
            printf(", ");
            
        // Add newline after every 8 bytes for readability
        if((i + 1) % 8 == 0 || i == nbytes - 1)
            printf("\n");
    }
    
    printf("};\n\n");
    printf("// Size of the binary data\n");
    printf("static const size_t binary_length = %u;\n", nbytes);
    
    // Clean up
    free(code);
    return 0;
}