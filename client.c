/*
 *  client.c
 *  OpenSSL
 *
 *  Created by Thirumal Venkat on 18/05/16.
 *  Copyright © 2016 Thirumal Venkat. All rights reserved.
 */

#include <openssl/bio.h>
#include <openssl/ssl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/bio.h>
#include <openssl/ssl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/time.h>
#include <memory.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netdb.h>
#include "client.h"

#define BUFSIZE 128

static SSL_CTX *get_client_context(const char *ca_pem,
                                   const char *cert_pem,
                                   const char *key_pem)
{
    SSL_CTX *ctx;

    /* Create a generic context */
    if (!(ctx = SSL_CTX_new(SSLv23_client_method())))
    {
        fprintf(stderr, "Cannot create a client context\n");
        return NULL;
    }

    /* Load the client's CA file location */
    if (SSL_CTX_load_verify_locations(ctx, ca_pem, NULL) != 1)
    {
        fprintf(stderr, "Cannot load client's CA file\n");
        goto fail;
    }

    /* Load the client's certificate */
    if (SSL_CTX_use_certificate_file(ctx, cert_pem, SSL_FILETYPE_PEM) != 1)
    {
        fprintf(stderr, "Cannot load client's certificate file\n");
        goto fail;
    }

    /* Load the client's key */
    if (SSL_CTX_use_PrivateKey_file(ctx, key_pem, SSL_FILETYPE_PEM) != 1)
    {
        fprintf(stderr, "Cannot load client's key file\n");
        goto fail;
    }

    /* Verify that the client's certificate and the key match */
    if (SSL_CTX_check_private_key(ctx) != 1)
    {
        fprintf(stderr, "Client's certificate and key don't match\n");
        goto fail;
    }

    /* We won't handle incomplete read/writes due to renegotiation */
    SSL_CTX_set_mode(ctx, SSL_MODE_AUTO_RETRY);

    /* Specify that we need to verify the server's certificate */
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);

    /* We accept only certificates signed only by the CA himself */
    SSL_CTX_set_verify_depth(ctx, 1);

    /* Done, return the context */
    return ctx;

fail:
    SSL_CTX_free(ctx);
    return NULL;
}

int openConnection(const char *source_ip, const char *conn_str, int port)
{
    int sockfd;
    int opt = 1;
    struct sockaddr_in cliaddr, servaddr;

    if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0)
    {
        perror("socket() error");
        return -1;
    }

    if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, &opt, sizeof(opt)))
    {
        perror("setsockopt");
        exit(EXIT_FAILURE);
    }

    memset(&cliaddr, 0, sizeof(cliaddr));
    cliaddr.sin_family = AF_INET;
    inet_pton(AF_INET, source_ip, &cliaddr.sin_addr);
    //cliaddr.sin_port = htons(atoi(port));
    printf("Ipv4 socket created\n");

    if (bind(sockfd, (struct sockaddr *)&cliaddr, sizeof(cliaddr)) < 0)
    {
        perror("bind() error");
        return -1;
    }

    memset(&servaddr, 0, sizeof(servaddr));
    servaddr.sin_family = AF_INET;
    inet_pton(AF_INET, conn_str, &servaddr.sin_addr);
    servaddr.sin_port = htons(port); /* HTTPS */

    if (connect(sockfd, (struct sockaddr *)&servaddr, sizeof(servaddr)) < 0)
    {
        perror("connect() error\n");
        return -1;
    }
    return sockfd;
}

int client(const char *conn_str, const char *ca_pem,
           const char *cert_pem, const char *key_pem)
{
    static char buffer[BUFSIZE];
    SSL_CTX *ctx;
    BIO *sbio;
    SSL *ssl;
    size_t len;
    /* Failure till we know it's a success */
    int rc = -1;
    struct timeval tv;

    int sockfd = openConnection("127.0.0.1", "127.0.0.1", 8888);
//*******************************************************************************************************
    /* Initialize OpenSSL */
    SSL_load_error_strings();
    OpenSSL_add_ssl_algorithms();

    /* Get a context */
    if (!(ctx = get_client_context(ca_pem, cert_pem, key_pem)))
    {
        return rc;
    }

   if ((ssl = SSL_new(ctx)) == NULL)
   {
      fprintf(stderr, "SSL_new() error\n");
      goto fail1;
   }

  SSL_set_connect_state(ssl);
   SSL_set_mode(ssl, SSL_MODE_AUTO_RETRY);
   SSL_set_read_ahead(ssl, 1);
   tv.tv_sec = 1; // 1 seconds
   tv.tv_usec = 0;
   setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, (const char *)&tv, sizeof tv);
   if (SSL_set_fd(ssl, sockfd) != 1)
   {
      fprintf(stderr, "SSL_set_fd() error\n");
      goto fail1;
   }
   //handshaking
   if (SSL_connect(ssl) != 1)
   {
      fprintf(stderr, "SSL_connect() error\n");
      goto fail1;
   }

    /* Verify that SSL handshake completed successfully */
    if (SSL_get_verify_result(ssl) != X509_V_OK)
    {
        fprintf(stderr, "Verification of handshake failed\n");
        goto fail2;
    }

    /* Inform the user that we've successfully connected */
    printf("SSL handshake successful with %s\n", conn_str);

    /* Read a line from the user */
    if (!fgets(buffer, BUFSIZE, stdin))
    {
        fprintf(stderr, "Could not read input from the user\n");
        goto fail3;
    }

    /* Get the length of the buffer */
    len = strlen(buffer);
//********************************************************************************************************************
    /* Write the input onto the SSL socket */
    if ((rc = SSL_write(ssl, buffer, (int)len)) != len)
    {
        fprintf(stderr, "Cannot write to the server\n");
        goto fail3;
    }

    /* Read from the server */
    if ((rc = SSL_read(ssl, buffer, BUFSIZE)) < 0)
    {
        fprintf(stderr, "Cannot read from the server\n");
        goto fail3;
    }

    /* Check if we've got back what we sent? (Not perfect, but OK for us) */
    if (len == rc)
    {
        /* Print it on the screen again */
        printf("%s", buffer);
    }

    rc = 0;

    /* Cleanup and exit */
fail3:
    printf("fail3");
fail2:
    printf("fail2");
fail1:
    SSL_CTX_free(ctx);
    return rc;
}
