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
#define CACHED_RESULTS 5
#define TIMEFORMAT "%Y-%m-%dT%H:%M:%S%z "
#define TIMESIZE 26
#define DNS_HEADER_SIZE 12
#define IPV6_TYPE 28


void log_request(FILE *fptr, char **labels, int num_labels) {
    printf("Logging request\n");
    log_timestamp(fptr);
    fprintf(fptr, "requested ");
    fflush(fptr);
    for (int i=0; i<num_labels; i++) {
        if (i == num_labels - 1) {
            fprintf(fptr, "%s", labels[i]);
            fflush(fptr);
            
        }
        else {
            fprintf(fptr, "%s.", labels[i]);
            fflush(fptr);
        }
    }
    fprintf(fptr, "\n");
    fflush(fptr);
}

// Only log first response
void log_response(FILE *fptr, char **labels, int num_labels, unsigned char *address, int num_elements) {
    log_timestamp(fptr);

    // Print domain name
    for (int i=0; i<num_labels; i++) {
        fprintf(fptr, "%s", labels[i]);
        fflush(fptr);
        if (i != num_labels - 1) {
            fprintf(fptr, ".");
            fflush(fptr);
        }
    }

    fprintf(fptr, " is at ");
    fflush(fptr);

    char ipv6_address[INET6_ADDRSTRLEN];
    inet_ntop(AF_INET6, address, ipv6_address, INET6_ADDRSTRLEN);

    // Print ipv6 address
    fprintf(fptr, "%s\n", ipv6_address);
    fflush(fptr);
}


void log_timestamp(FILE *fptr) {
    time_t timer;
    char buffer[TIMESIZE];
    struct tm* tm_info;

    timer = time(NULL);
    tm_info = localtime(&timer);

    strftime(buffer, TIMESIZE, TIMEFORMAT, tm_info);

    fprintf(fptr, "%s", buffer);
    fflush(fptr);
}


void extract_address(unsigned char *response, int response_size, int finished_index, unsigned char **address, int *num_elements) {
    // Start of RDLENGTH
    int i = finished_index + 14;
    (*num_elements) = (response[i] << 8) | response[i+1];
    (*address) = malloc((*num_elements) * sizeof(unsigned char));
    for (int j=0; j<(*num_elements); j++) {
        (*address)[j] = response[i+2+j];
    }
    
}

// Problem child fix memory shit
int extract_labels(unsigned char *packet, char ***labels, int *labels_size, int *num_labels) {
    // Array for labels
    // NOT FREED
    *labels = malloc(sizeof(char*) * INITIAL_NUM_LABELS);
    *labels_size = INITIAL_NUM_LABELS;
    *num_labels = 0;
    
    int i=DNS_HEADER_SIZE;
    while (packet[i] != 0) {

        int label_size = packet[i];
        // Current label (Array of characters) + 1 for the null byte
        char label[label_size+1];
        i++;
        for (int j=0; j<label_size; j++) {
            label[j] = packet[i];
            i++;
        }
        label[label_size] = '\0';


        // Need to realloc more space
        if (*num_labels == *labels_size) {
            char **tmp = realloc(*labels, 2*(*labels_size)*sizeof(char*));
            if (tmp != NULL) {
                *labels = tmp;
            }
            (*labels_size) *= 2;
        }
        // NOT FREED
        (*labels)[*num_labels] = malloc((label_size+1)*sizeof(char));
        strcpy((*labels)[*num_labels], label);
        (*num_labels)++;
    }
    i++;

    return i;
}

int read_from_socket(unsigned char **packet, int sockfd) {
    // unsigned char buffer[20];
    unsigned char packet_length_bytes[2];
    int bytes_read = 0;
    int n;

    while (bytes_read < HEADER_SIZE) {
        n = read(sockfd, packet_length_bytes + bytes_read, HEADER_SIZE - bytes_read);
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
    int rem_len = (packet_length_bytes[0] << 8) | packet_length_bytes[1];

    // Read rest of packet
    // NOT FREED
    (*packet) = malloc(rem_len * sizeof(unsigned char));
    bytes_read = 0;

    while (bytes_read < rem_len) {
        n = read(sockfd, (*packet) + bytes_read, rem_len - bytes_read);
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

    return rem_len;
}

int check_query_type(unsigned char *packet, int label_finish_index) {
    int qtype = (packet[label_finish_index] << 8) | packet[label_finish_index+1];

    // Check if request for AAAA
    if (qtype == IPV6_TYPE) {
        return 1;
    }
    else {
        return 0;
    }
}

// Only look at first answer
int valid_response(unsigned char *response, int response_size, int finished_index) {
    // Skip of NAME section
    int i = finished_index + 6;
    int type = (response[i] << 8) | response[i+1];
    // These use the same naming schema as QTYPE and QCLASS above, and have the same values as above.

    // valid ipv6 address
    if (type == IPV6_TYPE) {
        return 1;
    }
    else {
        return 0;
    }
}

// TODO make sure this shit is right
void write_to_socket(int upstreamsockfd, unsigned char *response, int response_size) {
    unsigned char header_buff[HEADER_SIZE];
    header_buff[0] = response_size >> 8;
    header_buff[1] = response_size & 255;

    int n;
    n = write(upstreamsockfd, header_buff, HEADER_SIZE);
    if (n < 0) {
        perror("socket");
        exit(EXIT_FAILURE);
    }


    n = write(upstreamsockfd, response, response_size);
    if (n < 0) {
        perror("socket");
        exit(EXIT_FAILURE);
    }

}

void respond_to_unimplemented(unsigned char *packet, int sockfd) {
    // Write header to send back to client
    unsigned char length[2];
    length[0] = 0;
    length[1] = 12;
    int n;
    n = write(sockfd, length, 2);
    unsigned char error_packet[DNS_HEADER_SIZE];

    // ID
    error_packet[0] = packet[0];
    error_packet[1] = packet[1];

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

    for (int i=4; i<DNS_HEADER_SIZE; i++) {
        error_packet[i] = 0;
    }

    n = write(sockfd, error_packet, DNS_HEADER_SIZE);
    if (n < 0) {
        perror("socket");
        exit(EXIT_FAILURE);
    }
}

void add_to_cache(unsigned char *response, int response_size, unsigned char **cache, int *cache_size) {
    printf("Adding to cache\n");
    // Always store most recent result at cache_size
    // if cache is full, move everything up one
    if (*cache_size == 5) {
        rotate_left(cache, (*cache_size));
        free(cache[*cache_size]);
        cache[*cache_size] = malloc((response_size + HEADER_SIZE) * sizeof(unsigned char));
        // Since response pointer is pointing to something that will be freed, we should copy it into cache instead
        // to be freed
        unsigned char *to_be_cached_response = malloc((response_size + HEADER_SIZE) * sizeof(unsigned char));
        to_be_cached_response[0] = response_size >> 8;
        to_be_cached_response[1] = response_size & 255;
        // Copy response to temp
        memcpy(to_be_cached_response+HEADER_SIZE, response, response_size * sizeof(unsigned char));
        // copy temp to cache
        memcpy(cache[*cache_size], to_be_cached_response, (response_size+HEADER_SIZE) * sizeof(unsigned char));
        free(to_be_cached_response);
    }
    else {
        // malloc space for response + size of packet
        // Need a free
        cache[*cache_size] = malloc((response_size + HEADER_SIZE) * sizeof(unsigned char));
        unsigned char *to_be_cached_response = malloc((response_size + HEADER_SIZE) * sizeof(unsigned char));
        to_be_cached_response[0] = response_size >> 8;
        to_be_cached_response[1] = response_size & 255;
        // Copy response to temp
        memcpy(to_be_cached_response+HEADER_SIZE, response, response_size * sizeof(unsigned char));
        // copy temp to cache
        memcpy(cache[*cache_size], to_be_cached_response, (response_size+HEADER_SIZE) * sizeof(unsigned char));
        free(to_be_cached_response);
        (*cache_size)++;
    }

    // Can now read size from response
}

void rotate_left(unsigned char **cache, int cache_size) {
    printf("left rotation\n");
    if (cache_size < 1) return;
    for (int i=0; i<cache_size-1; i++) {
        cache[i] = cache[i+1];
    }
    printf("rotated\n");
}

void free_cache(unsigned char **cache, int cache_size) {
    for (int i=0; i<cache_size; i++) {
        free(cache[i]);
    }
}