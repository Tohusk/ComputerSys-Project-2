#include <unistd.h>
#include <stdio.h>
#include <math.h>
#include <arpa/inet.h>
// #define MAXIPV4LENGTH 10
#define HEADER_SIZE 2
#define ID_SIZE 2

int main(int argc, char* argv[]) {
    // char *ipv4_address = (char*)malloc(MAXIPV4LENGTH*sizeof(char));
    // int portNumber = atoi(argv[2]);
    // strcpy(ipv4_address, argv[1]);

    // Read header
    // 2 bytes = 2 * char
    size_t count = HEADER_SIZE * sizeof(char);
    unsigned char buffer[HEADER_SIZE];
    read(STDIN_FILENO, buffer, count);

    // First two bytes are remaining length
    int rem_len = (buffer[0] << 8) | buffer[1];

    printf("rem_len = %d\n", rem_len);

    unsigned char packet_buff[rem_len];
    read(STDIN_FILENO, packet_buff, rem_len * sizeof(char));
    
    // HEADER
    printf("Header\n");

    // An arbitrary 16 bit request identifier. The same ID is used in the response to the query so we can match them up.
    int ID = (packet_buff[0] << 8) | packet_buff[1];
    printf("ID = %d\n", ID);

    // A 1 bit flag specifying whether this message is a query (0) or a response (1).
    int QR = (packet_buff[2] >> 7) & 1;
    printf("QR = %d\n", QR);

    // A 4 bit field that specifies the query type. 
    // The possibilities are: - 0: Standard query - 1: Inverse query - 2: Server status request - 3-15: Reserved for future use
    int opcode = (packet_buff[2] >> 3) & 15;
    printf("opcode = %d\n", opcode);

    // 1 bit flag specifying if the message has been truncated.
    int TC = (packet_buff[2] >> 1) & 1;
    printf("TC = %d\n", TC);

    // 1 bit flag specifying if recursion is desired. If the DNS server we send our request to doesn’t know the answer to our query, it can recursively ask other DNS servers.
    int RD = packet_buff[2] & 1;
    printf("RD = %d\n", RD);

    int RCODE = packet_buff[3] & 15;
    printf("RCODE = %d\n", RCODE);

    // An unsigned 16 bit integer specifying the number of entries in the question section.
    int QD = (packet_buff[4] << 8) | packet_buff[5];
    printf("QD = %d\n", QD);

    int AN = (packet_buff[6] << 8) | packet_buff[7];
    printf("AN = %d\n", AN);

    int NS = (packet_buff[8] << 8) | packet_buff[9];
    printf("NS = %d\n", NS);

    int AR = (packet_buff[10] << 8) | packet_buff[11];
    printf("AR = %d\n", AR);

    // QUESTION

    // How to get started

    // Print the log.
    // Attempt to modularise your code and make it reusable (if you didn’t do so during implementation).
    
    return 0;
}
