#include "caching.h"
#include "log.h"
#include <stdlib.h>
#include <string.h>

#define TCP_HEADER_SIZE 2
#define ANSWER_TO_TTL_LENGTH 6
#define DNS_HEADER_SIZE 12



void add_to_cache(FILE *fptr, unsigned char *response, unsigned char **cache, int *cache_size) {
    int response_size = (response[0] << 8) | response[1];

    // Should look to evict before finding new if not cache size 5
    int first_expired_index;
    if ((first_expired_index = find_expired_entry(cache, (*cache_size))) != -1) {
        log_cache_replacement(fptr, cache[first_expired_index], response);
        free(cache[first_expired_index]);
        cache[first_expired_index] = malloc((response_size + TCP_HEADER_SIZE) * sizeof(unsigned char));
        memcpy(cache[first_expired_index], response, (response_size + TCP_HEADER_SIZE) * sizeof(unsigned char));
    } 
    // no expired entry to evict
    else {
        // Store newest at cache_size
        if (*cache_size == 5) {
            log_cache_replacement(fptr, cache[0], response);

            rotate_left(cache, (*cache_size));

            free(cache[*cache_size-1]);
            cache[*cache_size-1] = malloc((response_size + TCP_HEADER_SIZE) * sizeof(unsigned char));
            
            memcpy(cache[*cache_size-1], response, (response_size + TCP_HEADER_SIZE) * sizeof(unsigned char));
        }
        else {
            // malloc space for response + size of packet
            cache[*cache_size] = malloc((response_size + TCP_HEADER_SIZE) * sizeof(unsigned char));

            memcpy(cache[*cache_size], response, (response_size+TCP_HEADER_SIZE) * sizeof(unsigned char));
            (*cache_size)++;
        }
    }
}

void rotate_left(unsigned char **cache, int cache_size) {
    if (cache_size < 1) return;
    unsigned char *tmp = cache[0]; 
    for (int i=0; i<cache_size-1; i++) {
        cache[i] = cache[i+1];
    }
    cache[cache_size-1] = tmp;
}

void free_cache(unsigned char **cache, int cache_size) {
    for (int i=0; i<cache_size; i++) {
        free(cache[i]);
    }
}

void update_cache_time(unsigned char **cache, int cache_size, time_t seconds_past) {
    for (int i=0; i<cache_size; i++) {
        int j = get_answer_index(cache[i]);
        // j is start of Answer section, name
        j+=ANSWER_TO_TTL_LENGTH;
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

bool check_labels(unsigned char *response, char **labels) {
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
            return false;
        }
        current_label++;
    }
    return true;
}

// If label fields are the same
int response_in_cache(unsigned char **cache, int cache_size, char **labels, int labels_size) {
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

void amend_response(unsigned char *cached_response, unsigned char *query_packet) {
    cached_response[TCP_HEADER_SIZE] = query_packet[TCP_HEADER_SIZE];
    cached_response[TCP_HEADER_SIZE+1] = query_packet[TCP_HEADER_SIZE+1];
}

bool check_ttl(unsigned char *response) {
    int i = get_answer_index(response);
    i+=ANSWER_TO_TTL_LENGTH;
    // j is at start of TTL
    unsigned int ttl = (response[i] << 24) | (response[i+1] << 16) | (response[i+2] << 8) | response[i+3];
    if (ttl > 0) {
        return true;
    }
    else {
        return false;
    }
}

int find_expired_entry(unsigned char **cache, int cache_size) {
    for (int i=0; i<cache_size; i++) {
        int j = get_answer_index(cache[i]);
        // j is start of Answer section, name
        j+=ANSWER_TO_TTL_LENGTH;
        // j is at start of TTL
        unsigned int ttl = (cache[i][j] << 24) | (cache[i][j+1] << 16) | (cache[i][j+2] << 8) | cache[i][j+3];
        // If expired
        if (ttl == 0) {
            return i;
        }
    }
    return -1;
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