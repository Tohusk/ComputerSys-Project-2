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
#define TCP_HEADER_SIZE 2
#define CACHED_RESULTS 5
#define TIMEFORMAT "%Y-%m-%dT%H:%M:%S%z "
#define TIMESIZE 26
#define DNS_HEADER_SIZE 12
#define IPV6_TYPE 28


void log_request(FILE *fptr, char **labels, int num_labels) {
    // printf("Logging request\n");
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

void amend_response(unsigned char *cached_response, unsigned char *query_packet) {
    printf("amending response\n");
    printf("response ID before: %d\n", (cached_response[TCP_HEADER_SIZE] << 8) | cached_response[TCP_HEADER_SIZE+1]);
    cached_response[TCP_HEADER_SIZE] = query_packet[TCP_HEADER_SIZE];
    cached_response[TCP_HEADER_SIZE+1] = query_packet[TCP_HEADER_SIZE+1];
    printf("response ID after: %d\n", (cached_response[TCP_HEADER_SIZE] << 8) | cached_response[TCP_HEADER_SIZE+1]);
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


void extract_address(unsigned char *response, int finished_index, unsigned char **address, int *num_elements) {
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
    
    int index=DNS_HEADER_SIZE+TCP_HEADER_SIZE;
    while (packet[index] != 0) {

        int label_size = packet[index];
        // Current label (Array of characters) + 1 for the null byte
        char label[label_size+1];
        index++;
        for (int j=0; j<label_size; j++) {
            label[j] = packet[index];
            index++;
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
    index++;

    // Finished label index, start of qtype
    return index;
}

unsigned char *read_from_socket(int sockfd) {

    unsigned char *packet = malloc(TCP_HEADER_SIZE * sizeof(unsigned char));
    // NOT FREED
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
int valid_response(unsigned char *response, int finished_index) {
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
void write_to_socket(int upstreamsockfd, unsigned char *response) {
    int response_size = (response[0] << 8) | response[1];

    int n = write(upstreamsockfd, response, response_size + TCP_HEADER_SIZE);
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

    for (int i=4; i<DNS_HEADER_SIZE; i++) {
        error_packet[i] = 0;
    }

    n = write(sockfd, error_packet, DNS_HEADER_SIZE);
    if (n < 0) {
        perror("socket");
        exit(EXIT_FAILURE);
    }
}

void add_to_cache(FILE *fptr, unsigned char *response, unsigned char **cache, int *cache_size) {
    printf("Adding to cache\n");
    printf("Cache size is %d\n", *cache_size);
    int response_size = (response[0] << 8) | response[1];

    // Should look to evict before finding new if not cache size 5
    int first_expired_index;
    if ((first_expired_index = find_expired_entry(cache, (*cache_size))) != -1) {
        printf("expired entry\n");
        log_cache_replacement(fptr, cache[first_expired_index], response);
        free(cache[first_expired_index]);
        cache[first_expired_index] = malloc((response_size + TCP_HEADER_SIZE) * sizeof(unsigned char));
        memcpy(cache[first_expired_index], response, (response_size + TCP_HEADER_SIZE) * sizeof(unsigned char));
    } 
    // no expired entry to evict
    else {
        // TODO
        // Always store most recent result at 0
        // if cache is full, move everything right by 1
        if (*cache_size == 5) {
            printf("cache full\n");
            log_cache_replacement(fptr, cache[0], response);
            rotate_left(cache, (*cache_size));
            // Since response pointer is pointing to something that will be freed, we should copy it into cache instead
            // to be freed
            free(cache[*cache_size-1]);
            cache[*cache_size-1] = malloc((response_size + TCP_HEADER_SIZE) * sizeof(unsigned char));
            
            memcpy(cache[*cache_size-1], response, (response_size + TCP_HEADER_SIZE) * sizeof(unsigned char));
        }
        else {
            // malloc space for response + size of packet
            // Need a free
            cache[*cache_size] = malloc((response_size + TCP_HEADER_SIZE) * sizeof(unsigned char));

            // copy temp to cache
            memcpy(cache[*cache_size], response, (response_size+TCP_HEADER_SIZE) * sizeof(unsigned char));
            (*cache_size)++;
        }
    }
}

void rotate_left(unsigned char **cache, int cache_size) {
    printf("rotating\n");
    if (cache_size < 1) return;
    unsigned char *tmp = cache[0]; 
    for (int i=0; i<cache_size-1; i++) {
        cache[i] = cache[i+1];
    }
    cache[cache_size-1] = tmp;
}

void free_labels(char **labels, int num_labels) {
    for (int i=0; i<num_labels; i++) {
        free(labels[i]);
    }
    free(labels);
}

void free_cache(unsigned char **cache, int cache_size) {
    for (int i=0; i<cache_size; i++) {
        free(cache[i]);
    }
}

int get_answer_index(unsigned char *response) {
    //  response now includes length of total message 
    int i=DNS_HEADER_SIZE+TCP_HEADER_SIZE;
    while (response[i] != 0) {
        int label_size = response[i];
        // Current label (Array of characters) + 1 for the null byte
        i++;
        for (int j=0; j<label_size; j++) {
            i++;
        }
    }
    i++;
    return i+4;
}

void update_cache_time(unsigned char **cache, int cache_size, long seconds_past) {
    printf("Updating cache\n");
    for (int i=0; i<cache_size; i++) {
        int j = get_answer_index(cache[i]);
        // j is start of Answer section, name
        j+=6;
        // j is at start of TTL
        unsigned int ttl = (cache[i][j] << 24) | (cache[i][j+1] << 16) | (cache[i][j+2] << 8) | cache[i][j+3];
        unsigned int new_ttl;
        if (ttl - seconds_past < 0) {
            new_ttl = 0;
        }
        else {
            new_ttl = ttl - seconds_past;
        }

        cache[i][j] = new_ttl >> 24;
        cache[i][j+1] = new_ttl >> 16;
        cache[i][j+2] = new_ttl >> 8;
        cache[i][j+3] = new_ttl & 16777215;
    }
}

// What if name and labels don't match up?

// If label fields are the same
int response_in_cache(unsigned char **cache, int cache_size, char **labels, int labels_size) {
    printf("Checking if response is in cache\n");
    if (cache_size != 0) {
        // Go through all the cache entries
        for (int i=cache_size-1; i>=0; i--) {
            unsigned char *response = cache[i];
            if (check_labels(response, labels) && check_ttl(response)) {
                return i;
            }
        }
    }
    return -1;
}

int check_labels(unsigned char *response, char **labels) {
    // Check if cache entry has expired
    int i=DNS_HEADER_SIZE+TCP_HEADER_SIZE;
    int current_label = 0;
    while (response[i] != 0) {

        int label_size =response[i];
        char label[label_size+1];
        // Current label (Array of characters) + 1 for the null byte
        i++;
        for (int j=0; j<label_size; j++) {
            label[j] = response[i];
            i++;
        }
        label[label_size] = '\0';
        // If label isn't the same return false
        if (strcmp(label, labels[current_label]) != 0) {
            return 0;
        }
        current_label++;
    }
    return 1;
}

int check_ttl(unsigned char *response) {
    int i = get_answer_index(response);
    i+=6;
    // j is at start of TTL
    unsigned int ttl = (response[i] << 24) | (response[i+1] << 16) | (response[i+2] << 8) | response[i+3];
    if (ttl > 0) {
        return 1;
    }
    else {
        return 0;
    }
}

int find_expired_entry(unsigned char **cache, int cache_size) {
    for (int i=0; i<cache_size; i++) {
        int j = get_answer_index(cache[i]);
        // j is start of Answer section, name
        j+=6;
        // j is at start of TTL
        unsigned int ttl = (cache[i][j] << 24) | (cache[i][j+1] << 16) | (cache[i][j+2] << 8) | cache[i][j+3];
        // If expired
        if (ttl == 0) {
            return i;
        }
    }
    return -1;
}

void log_cache_response_expiry(FILE *fptr, unsigned char *response, char **labels, int num_labels) {
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

    fprintf(fptr, " expires at ");
    fflush(fptr);

    time_t timer;
    char buffer[TIMESIZE];
    struct tm* tm_info;


    // Response here includes TCP header
    int i = get_answer_index(response);
    i+=6;
    // i is at start of TTL
    unsigned int ttl = (response[i] << 24) | (response[i+1] << 16) | (response[i+2] << 8) | response[i+3];
        
    timer = time(NULL);
    timer += ttl;
    tm_info = localtime(&timer);

    strftime(buffer, TIMESIZE, TIMEFORMAT, tm_info);

    fprintf(fptr, "%s", buffer);
    fflush(fptr);

    fprintf(fptr, "\n");
    fflush(fptr);
}

// both packets includes TCP header
void log_cache_replacement(FILE *fptr, unsigned char *expired_packet, unsigned char *to_be_cached_packet) {
    printf("replacing cache entry\n");
    char **expired_labels;
    int expired_labels_size;
    int expired_num_labels;

    extract_labels(expired_packet, &expired_labels, &expired_labels_size, &expired_num_labels);

    char **new_labels;
    int new_labels_size;
    int new_num_labels;

    extract_labels(to_be_cached_packet, &new_labels, &new_labels_size, &new_num_labels);

    log_timestamp(fptr);

    fprintf(fptr, "replacing ");
    fflush(fptr);

    // Print domain name
    for (int i=0; i<expired_num_labels; i++) {
        fprintf(fptr, "%s", expired_labels[i]);
        fflush(fptr);
        if (i != expired_num_labels - 1) {
            fprintf(fptr, ".");
            fflush(fptr);
        }
    }

    fprintf(fptr, " by ");
    fflush(fptr);

    for (int i=0; i<new_num_labels; i++) {
        fprintf(fptr, "%s", new_labels[i]);
        fflush(fptr);
        if (i != new_num_labels - 1) {
            fprintf(fptr, ".");
            fflush(fptr);
        }
    }

    fprintf(fptr, "\n");
    fflush(fptr);


    free_labels(expired_labels, expired_num_labels);

    free_labels(new_labels, new_num_labels);


}