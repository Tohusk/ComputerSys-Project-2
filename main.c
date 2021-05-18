#include <fcntl.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <time.h>
#include "helper1.h"

#define CACHED_RESULTS 5
#define CACHE


int main(int argc, char* argv[]) {

    
    // Store cache as response packets in array of (array of unsigned char)
    // ID needs to be modified when reading from cache
    unsigned char *cache[CACHED_RESULTS];
    int cache_size = 0;
    
    // Check if response is in cache

    // Read response from cache

    // Else send to upstream

    int first_timestamp = 1;


	int sockfd, newsockfd, re, s;
	struct addrinfo hints, *res;
	struct sockaddr_storage client_addr;
	socklen_t client_addr_size;

    if (argc < 3) {
        fprintf(stderr, "usage: %s <server-ip> <server-port>", argv[0]);
        exit(EXIT_FAILURE);
    }

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
    // printf("Server listening\n");


    // LOG 
    FILE *fptr;
    fptr = fopen("dns_svr.log", "w");    
    fclose(fptr);

    while (1) {
        // Accept a connection - blocks until a connection is ready to be accepted
        // Get back a new file descriptor to communicate on
        client_addr_size = sizeof client_addr;
        newsockfd = accept(sockfd, (struct sockaddr*)&client_addr, &client_addr_size);
        if (newsockfd < 0) {
            perror("accept");
            exit(EXIT_FAILURE);
        }
    
        FILE *fptr;
        fptr = fopen("dns_svr.log", "a");
    
        // printf("Client Connected\n");
        unsigned char *query_packet = read_from_socket(newsockfd);

        char **labels;
        int labels_size;
        int num_labels;

        // Finished index is first byte of qtype
        int finished_index = extract_labels(query_packet, &labels, &labels_size, &num_labels);
        log_request(fptr, labels, num_labels);

        // Wrong query type DO NOT FORWARD ANY QUERIES
        if (!check_query_type(query_packet, finished_index)) {
            log_timestamp(fptr);
            fprintf(fptr, "unimplemented request\n");
            fflush(fptr);
            // RESPOND WITH RCODE 4
            respond_to_unimplemented(query_packet, newsockfd);
        }
        else {
            // Check cache
            // Process TTL
            // ID fields
            // eviction behaviour 
            // Log

            // Update cache time
            time_t prev_timestamp;
            if (first_timestamp == 1) {
                prev_timestamp = time(NULL);
                first_timestamp = 0;
            }
            else {
                time_t current_timestamp = time(NULL);
                long seconds_past = current_timestamp - prev_timestamp;
                // Update cache TTL values
                update_cache_time(cache, cache_size, seconds_past);
            }


            // Check cache
            int response_index;
            if ((response_index = response_in_cache(cache, cache_size, labels, labels_size)) != -1) {
                printf("Response in cache at index %d\n", response_index);
                log_cache_response_expiry(fptr, cache[response_index], labels, num_labels);
                amend_response(cache[response_index], response_index, query_packet);
                // Skip first two bytes
                unsigned char *response = cache[response_index]+2;

                unsigned char *address;
                int num_elements;
                extract_address(response, finished_index, &address, &num_elements);
                log_response(fptr, labels, num_labels, address, num_elements);
                free(address);

                write_to_socket(newsockfd, response);
                free(query_packet);
                // TODO FIX WITH NEW FULL SIZE PACKET
            }


            // NOT IN CACHE
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
                        // printf("Connected to upstream\n");
                        break; // success
                    }
                    close(up_sockfd);
                }
                if (rp == NULL) {
                    fprintf(stderr, "Failed to connect to upstream\n");
                    exit(EXIT_FAILURE);
                }

                write_to_socket(up_sockfd, query_packet);
                // printf("Sent request to upstream\n");

                free(query_packet);

                // Read response from upstream
                unsigned char *response = read_from_socket(up_sockfd);

                // printf("Response read from upstream\n");


                if (valid_response(response, finished_index)) {
                    // Cache response
                    // Should evict expired ones first
                    add_to_cache(fptr, response, cache, &cache_size);

                    unsigned char *address;
                    int num_elements;
                    extract_address(response, finished_index, &address, &num_elements);
                    log_response(fptr, labels, num_labels, address, num_elements);
                    free(address);
                }

                close(up_sockfd);
                freeaddrinfo(servinfo);
                // Send full response to client
                write_to_socket(newsockfd, response);
                free(response);
            }
            // Free labels
            free_labels(labels, num_labels);



            // // Send full response to client
            // write_to_socket(newsockfd, response, response_size);
            // printf("Responded to client\n");
        }
        fclose(fptr);
    }

// The program should be ready to accept another query as soon as it has processed the previous query and response. (If Non-blocking option is implemented, it must be ready before this too.)

    // Close client to server socket
    freeaddrinfo(res);
    close(newsockfd);
    close(sockfd);

    // free cache
    free_cache(cache, cache_size);
        
    return 0;
}