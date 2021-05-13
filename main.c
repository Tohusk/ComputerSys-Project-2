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

    // /etc/resolv.conf 53
    if (argc < 3) {
        fprintf(stderr, "usage: %s <server-ip> <server-port>", argv[0]);
        exit(EXIT_FAILURE);
    }

    // LOG 
    FILE *fptr;
    fptr = fopen("dns_svr.log", "w");

    while (1) {

    

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

        int enable = 1; 
        if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(int)) < 0) { 
            perror("setsockopt"); 
            exit(1);
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

        printf("Server listening\n");

        // Accept a connection - blocks until a connection is ready to be accepted
        // Get back a new file descriptor to communicate on
        client_addr_size = sizeof client_addr;
        newsockfd = accept(sockfd, (struct sockaddr*)&client_addr, &client_addr_size);
        if (newsockfd < 0) {
            perror("accept");
            exit(EXIT_FAILURE);
        }

        printf("Client Connected\n");
        unsigned char *packet;
        int packet_size = read_packet(&packet, newsockfd);


        char **labels;
        int labels_size;
        int num_labels;

        int finished_index = extract_labels(packet, &labels, &labels_size, &num_labels);
        for (int i=0; i<labels_size; i++) {
            printf("label: %s\n", labels[i]);
        }
        log_request(fptr, labels, num_labels);

        // Wrong query type DO NOT FORWARD ANY QUERIES
        if (!check_query_type(packet, finished_index)) {
            log_timestamp(fptr);
            fprintf(fptr, "unimplemented request\n");
            // RESPOND WITH RCODE 4
            respond_to_unimplemented(packet, newsockfd);
        }
        else {
            // FORWARD TO UPSTREAM
            int up_sockfd, up_s;
            struct addrinfo up_hints, *servinfo, *rp;

            // Create address
            memset(&up_hints, 0, sizeof up_hints);
            up_hints.ai_family = AF_INET;
            up_hints.ai_socktype = SOCK_STREAM;

            // Connect to upstream
            up_s = getaddrinfo(argv[1], argv[2], &up_hints, &servinfo);
            if (up_s != 0) {
                fprintf(stderr, "getaddrinfo %s\n", gai_strerror(up_s));
                exit(EXIT_FAILURE);
            }


            // Connect to first valid result
            // Why are there multiple results? see man page (search 'several reasons')
            // How to search? enter /, then text to search for, press n/N to navigate
            for (rp = servinfo; rp != NULL; rp = rp->ai_next) {
                up_sockfd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
                if (up_sockfd == -1) {
                    continue;
                }
                if (connect(up_sockfd, rp->ai_addr, rp->ai_addrlen) != -1) {
                    printf("Connected to upstream\n");
                    break; // success
                }
                close(up_sockfd);
            }
            if (rp == NULL) {
                fprintf(stderr, "Failed to connect to upstream\n");
                exit(EXIT_FAILURE);
            }

            write_response(up_sockfd, packet, packet_size);
            printf("Sent request to upstream\n");

            // Read response from upstream
            unsigned char *response;
            int response_size = read_packet(&response, up_sockfd);

            printf("Response read from upstream\n");


            unsigned char *address;
            int num_elements;
            extract_address(response, response_size, finished_index, &address, &num_elements);
            log_response(fptr, labels, num_labels, address, num_elements);

            close(up_sockfd);
            freeaddrinfo(servinfo);

            // Send response to client
            write_response(newsockfd, response, response_size);
            printf("Responded to client\n");
        }


        

        // Close client to server socket
        freeaddrinfo(res);
        close(newsockfd);
        close(sockfd);
        
    }
    return 0;
}