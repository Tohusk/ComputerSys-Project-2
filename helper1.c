#include "helper1.h"
#include <fcntl.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <time.h>
#include <arpa/inet.h>


#define INITIAL_NUM_LABELS 2
#define HEADER_SIZE 2

void log_request(FILE *fptr, char **labels, int num_labels) {
    printf("Logging request\n");
    log_timestamp(fptr);
    fprintf(fptr, "requested ");
    for (int i=0; i<num_labels; i++) {
        if (i == num_labels - 1) {
            fprintf(fptr, "%s", labels[i]);
        }
        else {
            fprintf(fptr, "%s.", labels[i]);            
        }
    }
    fprintf(fptr, "\n");
}

// USE ntop
void log_response(FILE *fptr, char **labels, int num_labels, unsigned char *address, int num_elements) {
    log_timestamp(fptr);

    // Print domain name
    for (int i=0; i<num_labels; i++) {
        fprintf(fptr, "%s", labels[i]);
        if (i != num_labels - 1) {
            fprintf(fptr, ".");
        }
    }

    fprintf(fptr, " is at ");

    char ipv6_address[INET6_ADDRSTRLEN];
    inet_ntop(AF_INET6, address, ipv6_address, INET6_ADDRSTRLEN);

    // Print ipv6 address
    fprintf(fptr, "%s\n", ipv6_address);
}


void log_timestamp(FILE *fptr) {
    time_t timer;
    char buffer[26];
    struct tm* tm_info;

    timer = time(NULL);
    tm_info = localtime(&timer);

    strftime(buffer, 26, "%Y-%m-%dT%H:%M:%S+0000 ", tm_info);

    fprintf(fptr, "%s", buffer);
}

int extract_labels(unsigned char *packet_buff, char ***labels, int *labels_size, int *num_labels) {
    *labels = malloc(sizeof(char*) * INITIAL_NUM_LABELS);
    *labels_size = INITIAL_NUM_LABELS;
    *num_labels = 0;
    
    int i=12;
    while (packet_buff[i] != 0) {

        int label_size = packet_buff[i];
        char *label = malloc(label_size*sizeof(char));
        i++;
        for (int j=0; j<label_size; j++) {
            label[j] = packet_buff[i];
            i++;
        }

        // Need to realloc more space
        if (*num_labels == *labels_size) {
            *labels = realloc(*labels, 2*(*labels_size)*sizeof(char*));
            (*labels_size) *= 2;
        }
        (*labels)[*num_labels] = malloc(label_size*sizeof(char));
        strcpy((*labels)[*num_labels], label);
        (*num_labels)++;
    }
    i++;

    return i;
}

int read_packet(unsigned char **packet, int sockfd) {
    unsigned char buffer[20];
    unsigned char packet_length_bytes[2];
    int bytes_read = 0;
    
    // Read length
    while (1) {
        int n;
        n = read(sockfd, buffer, 2);
        if (n < 0) {
			perror("ERROR reading from socket");
			exit(EXIT_FAILURE);
		}

        if (n == 0) {
            printf("disconnect\n");
            break;
        }

        printf("n is %d\n", n);
        // Move onto storage
        for (int i=0; i<n; i++) {
            packet_length_bytes[bytes_read + i] = buffer[i];
        }
        bytes_read += n;

        if (bytes_read == 2) {
            break;
        }
    }

    // First two bytes are remaining length
    int rem_len = (packet_length_bytes[0] << 8) | packet_length_bytes[1];

    printf("rem_len = %d\n", rem_len);

    // Read rest of packet
    (*packet) = malloc(rem_len * sizeof(unsigned char));
    bytes_read = 0;
    while (1) {
        int n;
        n = read(sockfd, buffer, 20);
        if (n < 0) {
			perror("ERROR reading from socket");
			exit(EXIT_FAILURE);
		}

        if (n == 0) {
            printf("disconnect\n");
            break;
        }

        printf("n is %d\n", n);
        // Move onto storage
        for (int i=0; i<n; i++) {
            (*packet)[bytes_read + i] = buffer[i];
        }
        bytes_read += n;

        if (bytes_read == rem_len) {
            break;
        }
    }

    return rem_len;
}

int check_query_type(unsigned char *packet_buff, int label_finish_index) {
    int qtype = (packet_buff[label_finish_index] << 8) | packet_buff[label_finish_index+1];
    // Check if request for AAAA
    if (qtype == 28) {
        return 1;
    }
    else {
        return 0;
    }
}

// TODO make sure this shit is right
void write_response(int upstreamsockfd, unsigned char *response, int response_size) {


    
    unsigned char header_buff[HEADER_SIZE];
    header_buff[0] = response_size >> 8;
    header_buff[1] = response_size & 255;

    int n;
    n = write(upstreamsockfd, header_buff, HEADER_SIZE);
    if (n < 0) {
        perror("socket");
        exit(EXIT_FAILURE);
    }
    printf("after writing header: n is %d\n", n);


    n = write(upstreamsockfd, response, response_size);
    if (n < 0) {
        perror("socket");
        exit(EXIT_FAILURE);
    }
    printf("n is %d\n", n);

}
