#include "socket.h"
#include "log.h"
#include <stdlib.h>
#include <unistd.h>

#define TCP_HEADER_SIZE 2
#define DNS_HEADER_SIZE 12





unsigned char *read_from_socket(int sockfd) {
    unsigned char *packet = malloc(TCP_HEADER_SIZE * sizeof(unsigned char));
    int bytes_read = 0;
    int n;

    while (bytes_read < TCP_HEADER_SIZE) {
        n = read(sockfd, packet + bytes_read, TCP_HEADER_SIZE - bytes_read);
        if (n < 0) {
        	perror("ERROR reading from socket");
			exit(EXIT_FAILURE);
        }
        if (n == 0) {
            printf("disconnect\n");
            break;
        }
        bytes_read += n;
    }

    // First two bytes are remaining length
    int rem_len = (packet[0] << 8) | packet[1];

    // Read rest of packet
    packet = realloc(packet, (rem_len+TCP_HEADER_SIZE) * sizeof(unsigned char));
    bytes_read = 0;

    while (bytes_read < rem_len) {
        n = read(sockfd, packet + TCP_HEADER_SIZE + bytes_read, rem_len - bytes_read);
        if (n < 0) {
        	perror("ERROR reading from socket");
			exit(EXIT_FAILURE);
        }
        if (n == 0) {
            printf("disconnect\n");
            break;
        }
        bytes_read += n;
    }
    return packet;
}

void write_to_socket(int upstreamsockfd, unsigned char *response) {
    int response_size = (response[0] << 8) | response[1];

    int n = write(upstreamsockfd, response, response_size + TCP_HEADER_SIZE);
    if (n < 0) {
        perror("socket");
        exit(EXIT_FAILURE);
    }
}

void respond_to_unimplemented(FILE *fptr, unsigned char *packet, int sockfd) {
    log_timestamp(fptr);
    fprintf(fptr, "unimplemented request\n");
    fflush(fptr);

    // Construct packet with only header with RCODE 4

    // Write header to send back to client
    unsigned char length[TCP_HEADER_SIZE];
    length[0] = 0;
    length[1] = DNS_HEADER_SIZE;

    int n;
    n = write(sockfd, length, TCP_HEADER_SIZE);
    if (n < 0) {
        perror("socket");
        exit(EXIT_FAILURE);
    }
    
    unsigned char error_packet[DNS_HEADER_SIZE];

    // ID
    error_packet[0] = packet[TCP_HEADER_SIZE];
    error_packet[1] = packet[TCP_HEADER_SIZE+1];

    // QR
    // OPCODE
    // AA
    // TC
    // RD
    error_packet[2] = 128;
    // RA
    // Z
    // RCODE
    error_packet[3] = 132;

    // 0 entries for question answer auth record and additional records
    for (int i=4; i<DNS_HEADER_SIZE; i++) {
        error_packet[i] = 0;
    }

    n = write(sockfd, error_packet, DNS_HEADER_SIZE);
    if (n < 0) {
        perror("socket");
        exit(EXIT_FAILURE);
    }
}