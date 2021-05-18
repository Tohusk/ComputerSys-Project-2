#include <stdbool.h> 


#ifndef PARSING_H
#define PARSING_H

// PARSING 
int extract_labels(unsigned char *packet_buff, char ***labels, int *labels_size, int *num_labels);
bool check_query_type(unsigned char *packet_buff, int label_finish_index);
void extract_address(unsigned char *response, int finished_index, unsigned char **address, int *num_elements);
bool valid_response(unsigned char *response, int finished_index);
void free_labels(char **labels, int num_labels);



#endif