#include <stdio.h>

#ifndef SOCKET_H
#define SOCKET_H


// SOCKET IO
unsigned char *read_from_socket(int sockfd);
void write_to_socket(int upstreamsockfd, unsigned char *response);
void respond_to_unimplemented(FILE *fptr, unsigned char *packet, int sockfd);


#endif