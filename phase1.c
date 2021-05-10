#include <unistd.h>
#include <stdio.h>
#include <math.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "helper1.h"

#define HEADER_SIZE 2
#define ID_SIZE 2
#define INITIAL_NUM_LABELS 2

int main(int argc, char* argv[]) {
    // char *ipv4_address = (char*)malloc(MAXIPV4LENGTH*sizeof(char));
    // int portNumber = atoi(argv[2]);
    // strcpy(ipv4_address, argv[1]);

    // LOG 
    FILE *fptr;
    fptr = fopen("dns_svr.log", "w");

    

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
    //TODO IF RESPONSE THEN ANSWER SECTION ELSE NO
    int QR = (packet_buff[2] >> 7) & 1;
    printf("QR = %d\n", QR);

    // A 4 bit field that specifies the query type. 
    // The possibilities are: - 0: Standard query - 1: Inverse query - 2: Server status request - 3-15: Reserved for future use
    int opcode = (packet_buff[2] >> 3) & 15;
    printf("OPCODE = %d\n", opcode);

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
    printf("Question\n");


    // This contains the URL who’s IP address we wish to find. 
    // It is encoded as a series of ‘labels’. 
    // Each label corresponds to a section of the URL. 
    // The URL example.com contains two sections, example, and com.
    char **labels;
    int labels_size;
    int num_labels;

    int i = extract_labels(packet_buff, &labels, &labels_size, &num_labels);
    if (QR == 0) {
        log_request(fptr, labels, num_labels);
    }

    // The DNS record type we’re looking up. 
    int QTYPE = (packet_buff[i] << 8) | packet_buff[i+1];
    printf("QTYPE = %d\n", QTYPE);
    // 28 record type corresponds to AAAA
    // 1 record type corresponds to A

    int QCLASS = (packet_buff[i+2] << 8) | packet_buff[i+3];
    printf("QCLASS = %d\n", QCLASS);
    // IN CLASS
    printf("Current byte: %d\n", i);
    // Print the log.
    // Attempt to modularise your code and make it reusable (if you didn’t do so during implementation).

    // Reset index
    i=i+4;

    // ANSWER
    // IF NO ANSWER OR NOT IPV6 DON'T LOG ANYHTING
    printf("first two bits=%d\n", packet_buff[i] >> 6);
    if (QR == 1 && packet_buff[i] >> 6 == 3) {
        // NAME This is the URL who’s IP address this response contains. offset doesn't include the two leading bytes for length of entire message
        unsigned int NAME = ((packet_buff[i] & 63) << 8) | packet_buff[i+1];
        printf("NAME = %d\n", NAME);

        // These use the same naming schema as QTYPE and QCLASS above, and have the same values as above.
        int TYPE = (packet_buff[i+2] << 8) | packet_buff[i+3];
        printf("TYPE = %d\n", TYPE);

        int CLASS = (packet_buff[i+4] << 8) | packet_buff[i+5];
        printf("CLASS = %d\n", CLASS);

        // A 32-bit unsigned integer specifying the time to live for this Response, measured in seconds. Before this time interval runs out, the result can be cached. After, it should be discarded.
        unsigned int TTL = (packet_buff[i+6] << 24) | (packet_buff[i+7] << 16) | (packet_buff[i+8] << 8) | packet_buff[i+9];
        printf("TTL = %d\n", TTL);

        // RDLENGTH: The byte length of the following RDDATA section.
        int RDLENGTH= (packet_buff[i+10] << 8) | packet_buff[i+11];
        printf("RDLENGTH = %d\n", RDLENGTH);


        if (QTYPE != 28) {
            log_timestamp(fptr);
            fprintf(fptr, "unimplemented request\n");
        }


        // RDDATA: The IP address IPV6 addresses are 128 bits (network byte order) (high order first)
        // int RDDATA = (packet_buff[i+12])
        unsigned char address[RDLENGTH];
        for (int j=0; j<RDLENGTH; j++) {
            address[j] = packet_buff[i+12+j];
        }

        for (int j=0; j<RDLENGTH; j++) {
            printf("address = %x\n", address[j]);
        }

        // response
        log_response(fptr, labels, num_labels, address, RDLENGTH);

    }


    



    
    return 0;
}