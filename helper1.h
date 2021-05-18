#include <stdio.h>

#ifndef HELPER1_H
#define HELPER1_H


void log_request(FILE *fptr, char **labels, int num_labels);
void log_response(FILE *fptr, char **labels, int num_labels, unsigned char *address, int num_elements);
void log_timestamp(FILE *fptr);
int extract_labels(unsigned char *packet_buff, char ***labels, int *labels_size, int *num_labels);
unsigned char *read_from_socket(int sockfd);
int check_query_type(unsigned char *packet_buff, int label_finish_index);
void write_to_socket(int upstreamsockfd, unsigned char *response);
void extract_address(unsigned char *response, int finished_index, unsigned char **address, int *num_elements);
void respond_to_unimplemented(unsigned char *packet, int sockfd);
int valid_response(unsigned char *response, int finished_index);
void add_to_cache(FILE *fptr, unsigned char *response, unsigned char **cache, int *cache_size);
void rotate_left(unsigned char **cache, int cache_size);
void free_cache(unsigned char **cache, int cache_size);
void update_cache_time(unsigned char **cache, int cache_size, long seconds_past);
int check_labels(unsigned char *response, char **labels);
int response_in_cache(unsigned char **cache, int cache_size, char **labels, int labels_size);
void amend_response(unsigned char *cached_response, unsigned char *query_packet);
int check_ttl(unsigned char *response);
int find_expired_entry(unsigned char **cache, int cache_size);
void log_cache_response_expiry(FILE *fptr, unsigned char *response, char **labels, int num_labels);
void log_cache_replacement(FILE *fptr, unsigned char *expired_packet, unsigned char *to_be_cached_packet);
void free_labels(char **labels, int num_labels);
#endif