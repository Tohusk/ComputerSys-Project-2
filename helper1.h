#include <stdio.h>

#ifndef HELPER1_H
#define HELPER1_H


void log_request(FILE *fptr, char **labels, int num_labels);
void log_response(FILE *fptr, char **labels, int num_labels, unsigned char *address, int num_elements);
void log_timestamp(FILE *fptr);
int extract_labels(unsigned char *packet_buff, char ***labels, int *labels_size, int *num_labels);
void read_packet(unsigned char **packet_buffer, int sockfd);
int check_query_type(unsigned char *packet_buff, int label_finish_index);

#endif