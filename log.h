#include <stdio.h>

// LOGGING
void log_request(FILE *fptr, char **labels, int num_labels);
void log_response(FILE *fptr, char **labels, int num_labels, unsigned char *address, int num_elements);
void log_timestamp(FILE *fptr);
// Caching
void log_cache_response_expiry(FILE *fptr, unsigned char *response, char **labels, int num_labels);
void log_cache_replacement(FILE *fptr, unsigned char *expired_packet, unsigned char *to_be_cached_packet);

