#include <fcntl.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include "helper1.h"




int main(int argc, char* argv[]) {
	int sockfd, newsockfd, re, s;
	struct addrinfo hints, *res;
	struct sockaddr_storage client_addr;
	socklen_t client_addr_size;

    // NOT IMPLEMENTED YET
    // /etc/resolv.conf 53
    if (argc < 3) {
        fprintf(stderr, "usage: %s <server-ip> <server-port>", argv[0]);
        exit(EXIT_FAILURE);
    }

    // LOG 
    FILE *fptr;
    fptr = fopen("dns_svr.log", "w");


	// Create address we're going to listen on (with given port number)
    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE;
    s = getaddrinfo(NULL, "8053", &hints, &res);
    if (s != 0) {
        fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(s));
        exit(EXIT_FAILURE);
    }

    // Create socket
	sockfd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
	if (sockfd < 0) {
		perror("socket");
		exit(EXIT_FAILURE);
	}

    // Reuse port if possible
	re = 1;
	if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &re, sizeof(int)) < 0) {
		perror("setsockopt");
		exit(EXIT_FAILURE);
	}

	// Bind address to the socket
	if (bind(sockfd, res->ai_addr, res->ai_addrlen) < 0) {
		perror("bind");
		exit(EXIT_FAILURE);
	}

    // Listen on socket - means we're ready to accept connections,
	// incoming connection requests will be queued, man 3 listen
	if (listen(sockfd, 5) < 0) {
		perror("listen");
		exit(EXIT_FAILURE);
	}

    // Accept a connection - blocks until a connection is ready to be accepted
	// Get back a new file descriptor to communicate on
	client_addr_size = sizeof client_addr;
	newsockfd =
		accept(sockfd, (struct sockaddr*)&client_addr, &client_addr_size);
	if (newsockfd < 0) {
		perror("accept");
		exit(EXIT_FAILURE);
	}

    printf("Client Connected\n");
    unsigned char *packet_buff;
    read_packet(&packet_buff, newsockfd);

    char **labels;
    int labels_size;
    int num_labels;

    int finished_index = extract_labels(packet_buff, &labels, &labels_size, &num_labels);
    log_request(fptr, labels, num_labels);

    // Check unimplemented request
    int qtype = (packet_buff[finished_index] << 8) | packet_buff[finished_index+1];
    if (qtype != 28) {
        log_timestamp(fptr);
        fprintf(fptr, "unimplemented request\n");
    }

    



    // // FORWARD TO UPSTREAM
    // // If not AAAA record in request, don't forward to upstream
    // // Remember to log things


    // int upstreamsockfd, upstream_s;
    // struct addrinfo upstream_hints, *servinfo, *rp;

    // // Create address
    // memset(&upstream_hints, 0, sizeof upstream_hints);
	// upstream_hints.ai_family = AF_INET;
	// upstream_hints.ai_socktype = SOCK_STREAM;

    // // Connect to upstream
    // upstream_s = getaddrinfo(argv[1], argv[2], &upstream_hints, &servinfo);
    // if (upstream_s != 0) {
    //     fprintf(stderr, "getaddrinfo %s\n", gai_strerror(upstream_s));
    //     exit(EXIT_FAILURE);
    // }

    // // Connect to first valid result
	// // Why are there multiple results? see man page (search 'several reasons')
	// // How to search? enter /, then text to search for, press n/N to navigate
	// for (rp = servinfo; rp != NULL; rp = rp->ai_next) {
	// 	upstreamsockfd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
	// 	if (upstreamsockfd == -1)
	// 		continue;

	// 	if (connect(upstreamsockfd, rp->ai_addr, rp->ai_addrlen) != -1)
	// 		break; // success

	// 	close(upstreamsockfd);
	// }
	// if (rp == NULL) {
	// 	fprintf(stderr, "Failed to connect to upstream\n");
	// 	exit(EXIT_FAILURE);
	// }

    // printf("Connected to upstream\n");

    // int bytes_sent = 0;
    // // Need to handle socket errors
    // while (bytes_sent != rem_len) {
    //     bytes_sent += write(upstreamsockfd, buffer+bytes_sent, (rem_len - bytes_sent) * sizeof(unsigned char));
    // }

    // printf("Sent request to upstream\n");

    // // Read response from upstream
    // // Read header
    // // 2 bytes = 2 * char
	// unsigned char responsebuffer[HEADER_SIZE];
    // bytes_read = 0;
    // // Need to handle socket errors
    // while (bytes_read != HEADER_SIZE) {
    //     // Read one byte at a time for header
    //     bytes_read += read(upstreamsockfd, responsebuffer+bytes_read, sizeof(unsigned char));
    // }
    // // First two bytes are remaining length
    // rem_len = (responsebuffer[0] << 8) | responsebuffer[1];

    // unsigned char response_packet_buff[rem_len];
    // // Reset bytes read
    // bytes_read = 0;
    // while (bytes_read != rem_len) {
    //     bytes_read += read(upstreamsockfd, response_packet_buff+bytes_read, (rem_len - bytes_read)*sizeof(unsigned char));
    // }

    // printf("Response read from upstream\n");



    // close(upstreamsockfd);
    // freeaddrinfo(servinfo);

    // // Send response to client
    // bytes_sent = 0;
    // // Need to handle socket errors
    // while (bytes_sent != rem_len) {
    //     bytes_sent += write(newsockfd, response_packet_buff+bytes_sent, (rem_len - bytes_sent) * sizeof(unsigned char));
    // }

    // printf("Responded to client\n");

	freeaddrinfo(res);
	close(newsockfd);
	close(sockfd);
    
    return 0;
}