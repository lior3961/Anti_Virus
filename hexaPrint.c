#include <stdio.h>
#include <stdlib.h>

void PrintHex(unsigned char *buffer, size_t length) {
    for (size_t i = 0; i < length; i++) {
        printf("%02X ", buffer[i]);
    }
    printf("\n");
}
// Function to print a buffer in hexadecimal format

int main(int argc, char *argv[]) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s FILE\n", argv[0]);
        return 1;
    }

    const char *filename = argv[1];
    FILE *file = fopen(filename, "rb");
    if (file == NULL) {
        perror("Error opening file");
        return 1;
    }

    // Read the file in chunks
    unsigned char buffer[16];
    size_t bytesRead;
    while ((bytesRead = fread(buffer, 1, sizeof(buffer), file)) > 0) {
        PrintHex(buffer, bytesRead);
    }

    if (ferror(file)) {
        perror("Error reading file");
    }
    fclose(file);
    return 0;
}

