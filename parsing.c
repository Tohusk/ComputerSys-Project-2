#include "parsing.h"
#include <stdlib.h>
#include <string.h>


#define INITIAL_NUM_LABELS 2
#define DNS_HEADER_SIZE 12
#define TCP_HEADER_SIZE 2
#define IPV6_TYPE 28
#define ANCOUNT_INDEX 8





int extract_labels(unsigned char *packet, char ***labels, int *labels_size, int *num_labels) {
    // Array for labels
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
        (*labels)[*num_labels] = malloc((label_size+1)*sizeof(char));
        strcpy((*labels)[*num_labels], label);
        (*num_labels)++;
    }
    index++;

    // Finished label index, start of qtype
    return index;
}

bool check_query_type(unsigned char *packet, int label_finish_index) {
    int qtype = (packet[label_finish_index] << 8) | packet[label_finish_index+1];

    // Check if request for AAAA
    if (qtype == IPV6_TYPE) {
        return true;
    }
    else {
        return false;
    }
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

bool valid_response(unsigned char *response, int finished_index) {
    // Check num ANCOUNT > 0
    int answer_count = (response[ANCOUNT_INDEX] << 8) | response[ANCOUNT_INDEX+1];
    // Skip past NAME section to start of TYPE
    int i = finished_index + 6;
    int type = (response[i] << 8) | response[i+1];

    // valid ipv6 address and more than 1 answer
    if (answer_count > 0 && type == IPV6_TYPE) {
        return true;
    }
    else {
        return false;
    }
}

void free_labels(char **labels, int num_labels) {
    for (int i=0; i<num_labels; i++) {
        free(labels[i]);
    }
    free(labels);
}