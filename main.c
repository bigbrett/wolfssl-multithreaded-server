#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/socket.h>
#include <netinet/in.h>

#include <wolfssl/options.h>
#include <wolfssl/ssl.h>

#define PORT 11111
#define BUFFER_SIZE 1024

WOLFSSL_CTX *ctx; /* Global SSL context */

void *handleClient(void *arg);

int main() {
    int sockfd, *newsockfd;
    struct sockaddr_in serv_addr, cli_addr;
    socklen_t clilen;
    pthread_t thread;

    /* Initialize wolfSSL */
    wolfSSL_Init();

    /* Create and initialize WOLFSSL_CTX */
    ctx = wolfSSL_CTX_new(wolfTLSv1_3_server_method());
    if (ctx == NULL) {
        perror("ERROR creating WOLFSSL_CTX");
        exit(1);
    }

    /* Load server certificates */
    if (wolfSSL_CTX_use_certificate_file(ctx, "/home/brett/workspace/wolfssl/wolfssl-repos/wolfssl/certs/server-cert.pem", SSL_FILETYPE_PEM) != SSL_SUCCESS ||
        wolfSSL_CTX_use_PrivateKey_file(ctx,  "/home/brett/workspace/wolfssl/wolfssl-repos/wolfssl/certs/server-key.pem", SSL_FILETYPE_PEM) != SSL_SUCCESS) {
        perror("ERROR loading certificates");
        wolfSSL_CTX_free(ctx);
        exit(1);
    }

    /* Create a TCP socket */
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        perror("ERROR opening socket");
        exit(1);
    }

    /* Initialize socket structure */
    memset(&serv_addr, 0, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = INADDR_ANY;
    serv_addr.sin_port = htons(PORT);

    /* Bind the host address */
    if (bind(sockfd, (struct sockaddr *) &serv_addr, sizeof(serv_addr)) < 0) {
        perror("ERROR on binding");
        exit(1);
    }

    /* Start listening for clients */
    listen(sockfd, 5);
    clilen = sizeof(cli_addr);

    /* Accept actual connections from clients */
    while (1) {
        newsockfd = malloc(sizeof(int)); // Allocate memory for each connection's socket descriptor
        if (newsockfd == NULL) {
            perror("ERROR allocating memory for new socket");
            continue;
        }

        *newsockfd = accept(sockfd, (struct sockaddr *) &cli_addr, &clilen);
        if (*newsockfd < 0) {
            perror("ERROR on accept");
            free(newsockfd); // Free the allocated memory in case of error
            continue;
        }

        /* Spawn thread to handle client */
        pthread_attr_t attr;
        pthread_attr_init(&attr);
        pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);

        if (pthread_create(&thread, &attr, handleClient, (void *)newsockfd) < 0) {
            perror("ERROR creating thread");
            close(*newsockfd);
            free(newsockfd); // Free the allocated memory in case of error
        }
        pthread_attr_destroy(&attr);
    }

    /* Clean up */
    close(sockfd);
    wolfSSL_CTX_free(ctx);
    wolfSSL_Cleanup();
    return 0;
}

void *handleClient(void *arg) {
    int sock = *(int*)arg;
    WOLFSSL *ssl;
    char buffer[BUFFER_SIZE];
    int readSize;


    /* Create a WOLFSSL object */
    ssl = wolfSSL_new(ctx);
    if (ssl == NULL) {
        perror("ERROR creating WOLFSSL object");
        close(sock);
        return NULL;
    }

    /* Attach wolfSSL to the socket */
    wolfSSL_set_fd(ssl, sock);

    /* Perform TLS handshake */
    printf("[%d] accepting connection\n", sock);
    if (wolfSSL_accept(ssl) != SSL_SUCCESS) {
        perror("ERROR in SSL accept");
        wolfSSL_free(ssl);
        close(sock);
        return NULL;
    }
    printf("[%d] accepted\n", sock);


    /* Continuously read client data and echo back until client closes connection */
    while (1) {
        readSize = wolfSSL_read(ssl, buffer, sizeof(buffer)-1);

        printf("received %d bytes from sock %d\n", readSize, sock);

        if (readSize <= 0) {
            printf("received %d bytes, closing sock %d\n", readSize, sock);
            break;  // Break the loop if client closes connection or error occurs
        }

        buffer[readSize] = '\0';  // Null-terminate the string
        wolfSSL_write(ssl, buffer, readSize);  // Echo back the data
    }

    /* Clean up */
    wolfSSL_free(ssl);
    close(sock);
    return NULL;
}

