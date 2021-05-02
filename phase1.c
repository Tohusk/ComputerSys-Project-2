#include <unistd.h>
#include <stdio.h>
#include <math.h>
#include <arpa/inet.h>
// #define MAXIPV4LENGTH 10
#define HEADER_SIZE 2

int main(int argc, char* argv[]) {
    // char *ipv4_address = (char*)malloc(MAXIPV4LENGTH*sizeof(char));
    // int portNumber = atoi(argv[2]);
    // strcpy(ipv4_address, argv[1]);

    // Read header
    // 2 bytes = 2 * char
    printf("Reading Header\n");
    size_t count = HEADER_SIZE * sizeof(char);
    unsigned char buffer[HEADER_SIZE];
    read(STDIN_FILENO, buffer, count);

    // Need to get length of message from these two bytes
    // USE NTOHS OR NTOHL OR HTONS OR HTONL FROM WORKSHOP 7 Also, it would be 0x0034 (as 1 number) which would be the input.
    // Alternatively, you can left shift the first byte and bitwise OR the result with the second byte.

    // left shift first by 8 then or them
    int rem_len = buffer[0] << 8 | buffer[1];

    printf("rem_len = %d\n", rem_len);
    
    // we pass .raw files as stdin via ./phase1 < .raw

    // How to get started

    // Read specification
    // Start with reading the packet from stdin (standard input, STDIN_FILENO or file descriptor 0) stream using read(2) or read(3) man read call. Refer to 2.1 paragraph 2 about the first 2 bytes of the packet.
    // Recommendation: Print out/screenshot and annotate a hex dump of a DNS packet, referring to the mini-specification of the packet format (Reference [1] at end of specification).
    // Leave a couple of blank lines for your annotations, as the information can get quite dense.
    // Alternatively, capture a packet with wireshark and highlight the various fields relevant for the project or @615.
    // Alternatively, look at and understand the annotated sample: https://canvas.lms.unimelb.edu.au/courses/107590/assignments/205862
    // Extract the various field required for this project from packets using what you learnt from week 7 practical and what you learnt about DNS packet format in previous step.
    // Print the log.
    // Attempt to modularise your code and make it reusable (if you didn’t do so during implementation).
    
    return 0;
}
