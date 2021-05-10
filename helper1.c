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

void read_packet(unsigned char **packet_buff, int sockfd) {
    // Read header
    // 2 bytes = 2 * char
	unsigned char buffer[HEADER_SIZE];
    int bytes_read = 0;
    // Need to handle socket errors
    while (bytes_read != HEADER_SIZE) {
        // Read one byte at a time for header
        bytes_read += read(sockfd, buffer+bytes_read, sizeof(unsigned char));
    }
	
    // First two bytes are remaining length
    int rem_len = (buffer[0] << 8) | buffer[1];

    (*packet_buff) = malloc(sizeof(unsigned char) * rem_len);
    // Reset bytes read
    bytes_read = 0;
    while (bytes_read != rem_len) {
        bytes_read += read(sockfd, (*packet_buff)+bytes_read, (rem_len - bytes_read)*sizeof(unsigned char));
    }
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
