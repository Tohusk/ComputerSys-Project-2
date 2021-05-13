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
        // respond_to_unimplemented(newsockfd)
    }
    // else {
    //     // FORWARD TO UPSTREAM

    //     int up_sockfd, up_s;
    //     struct addrinfo up_hints, *servinfo, *rp;

    //     // Create address
    //     memset(&up_hints, 0, sizeof up_hints);
    //     up_hints.ai_family = AF_INET;
    //     up_hints.ai_socktype = SOCK_STREAM;

    //     // Connect to upstream
    //     up_s = getaddrinfo(argv[1], argv[2], &up_hints, &servinfo);
    //     if (up_s != 0) {
    //         fprintf(stderr, "getaddrinfo %s\n", gai_strerror(up_s));
    //         exit(EXIT_FAILURE);
    //     }


    //     // Connect to first valid result
    //     // Why are there multiple results? see man page (search 'several reasons')
    //     // How to search? enter /, then text to search for, press n/N to navigate
    //     for (rp = servinfo; rp != NULL; rp = rp->ai_next) {
    //     	up_sockfd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
    //     	if (up_sockfd == -1)
    //             continue;

    //     	if (connect(up_sockfd, rp->ai_addr, rp->ai_addrlen) != -1)
    //             printf("Connected to upstream\n");
    //     		break; // success

    //     	close(up_sockfd);
    //     }
    //     if (rp == NULL) {
    //     	fprintf(stderr, "Failed to connect to upstream\n");
    //     	exit(EXIT_FAILURE);
    //     }

    //     // // run packet through phase 1 to check validity
    //     // // HEADER
    //     // printf("Header\n");

    //     // // An arbitrary 16 bit request identifier. The same ID is used in the response to the query so we can match them up.
    //     // int ID = (packet[0] << 8) | packet[1];
    //     // printf("ID = %d\n", ID);

    //     // // A 1 bit flag specifying whether this message is a query (0) or a response (1).
    //     // //TODO IF RESPONSE THEN ANSWER SECTION ELSE NO
    //     // int QR = (packet[2] >> 7) & 1;
    //     // printf("QR = %d\n", QR);

    //     // // A 4 bit field that specifies the query type. 
    //     // // The possibilities are: - 0: Standard query - 1: Inverse query - 2: Server status request - 3-15: Reserved for future use
    //     // int opcode = (packet[2] >> 3) & 15;
    //     // printf("OPCODE = %d\n", opcode);

    //     // // 1 bit flag specifying if the message has been truncated.
    //     // int TC = (packet[2] >> 1) & 1;
    //     // printf("TC = %d\n", TC);

    //     // // 1 bit flag specifying if recursion is desired. If the DNS server we send our request to doesn’t know the answer to our query, it can recursively ask other DNS servers.
    //     // int RD = packet[2] & 1;
    //     // printf("RD = %d\n", RD);

    //     // int RCODE = packet[3] & 15;
    //     // printf("RCODE = %d\n", RCODE);

    //     // // An unsigned 16 bit integer specifying the number of entries in the question section.
    //     // int QD = (packet[4] << 8) | packet[5];
    //     // printf("QD = %d\n", QD);

    //     // int AN = (packet[6] << 8) | packet[7];
    //     // printf("AN = %d\n", AN);

    //     // int NS = (packet[8] << 8) | packet[9];
    //     // printf("NS = %d\n", NS);

    //     // int AR = (packet[10] << 8) | packet[11];
    //     // printf("AR = %d\n", AR);

    //     // // QUESTION
    //     // printf("Question\n");


    //     // // This contains the URL who’s IP address we wish to find. 
    //     // // It is encoded as a series of ‘labels’. 
    //     // // Each label corresponds to a section of the URL. 
    //     // // The URL example.com contains two sections, example, and com.
    //     // char **labels;
    //     // int labels_size;
    //     // int num_labels;

    //     // int i = extract_labels(packet, &labels, &labels_size, &num_labels);

    //     // // The DNS record type we’re looking up. 
    //     // int QTYPE = (packet[i] << 8) | packet[i+1];
    //     // printf("QTYPE = %d\n", QTYPE);
    //     // // 28 record type corresponds to AAAA
    //     // // 1 record type corresponds to A

    //     // int QCLASS = (packet[i+2] << 8) | packet[i+3];
    //     // printf("QCLASS = %d\n", QCLASS);
    //     // // IN CLASS
    //     // printf("Current byte: %d\n", i);
    //     // // Print the log.
    //     // // Attempt to modularise your code and make it reusable (if you didn’t do so during implementation).
    //     // // Reset index
    //     // i=i+4;

    //     // // ANSWER
    //     // // IF NO ANSWER OR NOT IPV6 DON'T LOG ANYHTING
    //     // printf("first two bits=%d\n", packet[i] >> 6);
    //     // if (QR == 1 && packet[i] >> 6 == 3 && QTYPE == 28) {
    //     //     // NAME This is the URL who’s IP address this response contains. offset doesn't include the two leading bytes for length of entire message
    //     //     unsigned int NAME = ((packet[i] & 63) << 8) | packet[i+1];
    //     //     printf("NAME = %d\n", NAME);

    //     //     // These use the same naming schema as QTYPE and QCLASS above, and have the same values as above.
    //     //     int TYPE = (packet[i+2] << 8) | packet[i+3];
    //     //     printf("TYPE = %d\n", TYPE);

    //     //     int CLASS = (packet[i+4] << 8) | packet[i+5];
    //     //     printf("CLASS = %d\n", CLASS);

    //     //     // A 32-bit unsigned integer specifying the time to live for this Response, measured in seconds. Before this time interval runs out, the result can be cached. After, it should be discarded.
    //     //     unsigned int TTL = (packet[i+6] << 24) | (packet[i+7] << 16) | (packet[i+8] << 8) | packet[i+9];
    //     //     printf("TTL = %d\n", TTL);

    //     //     // RDLENGTH: The byte length of the following RDDATA section.
    //     //     int RDLENGTH= (packet[i+10] << 8) | packet[i+11];
    //     //     printf("RDLENGTH = %d\n", RDLENGTH);



    //     //     // RDDATA: The IP address IPV6 addresses are 128 bits (network byte order) (high order first)
    //     //     // int RDDATA = (packet[i+12])
    //     //     unsigned char address[RDLENGTH];
    //     //     for (int j=0; j<RDLENGTH; j++) {
    //     //         address[j] = packet[i+12+j];
    //     //     }

    //     //     for (int j=0; j<RDLENGTH; j++) {
    //     //         printf("address = %x\n", address[j]);
    //     //     }

    //     // }

















    //     write_response(up_sockfd, packet, packet_size);
    //     printf("Sent request to upstream\n");

    //     // Read response from upstream
    //     // Read header
    //     // 2 bytes = 2 * char
    //     unsigned char *response_buffer;
    //     int response_buffer_size = read_packet(&response_buffer, newsockfd);

    //     printf("Response read from upstream\n");

    //     close(up_sockfd);
    //     freeaddrinfo(servinfo);

    //     // Send response to client
    //     write_response(newsockfd, response_buffer, response_buffer_size);

    //     // bytes_sent = 0;
    //     // // Need to handle socket errors
    //     // while (bytes_sent != rem_len) {
    //     //     bytes_sent += write(newsockfd, response_packet+bytes_sent, (rem_len - bytes_sent) * sizeof(unsigned char));
    //     // }

    //     printf("Responded to client\n");

    // }
    

    // Close client to server socket
	freeaddrinfo(res);
	close(newsockfd);
	close(sockfd);
    
    return 0;
}