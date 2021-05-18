#include <stdio.h>
#include <time.h>
#include <stdbool.h> 


#ifndef CACHING_H
#define CACHING_H

// CACHE MANAGEMENT
void add_to_cache(FILE *fptr, unsigned char *response, unsigned char **cache, int *cache_size);
void rotate_left(unsigned char **cache, int cache_size);
void free_cache(unsigned char **cache, int cache_size);
void update_cache_time(unsigned char **cache, int cache_size, time_t seconds_past);
bool check_labels(unsigned char *response, char **labels);
int response_in_cache(unsigned char **cache, int cache_size, char **labels, int labels_size);
void amend_response(unsigned char *cached_response, unsigned char *query_packet);
bool check_ttl(unsigned char *response);
int find_expired_entry(unsigned char **cache, int cache_size);
int get_answer_index(unsigned char *response);

#endif