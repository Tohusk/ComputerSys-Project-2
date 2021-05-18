#include "log.h"
#include "caching.h"
#include "parsing.h"
#include <netdb.h>
#include <arpa/inet.h>
#include <time.h>


#define TIMEFORMAT "%Y-%m-%dT%H:%M:%S%z "
#define TIMESIZE 26


void log_request(FILE *fptr, char **labels, int num_labels) {
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

void log_cache_replacement(FILE *fptr, unsigned char *expired_packet, unsigned char *to_be_cached_packet) {
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

    // Print expired domain name
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

    // Print new domain name
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