#include "uv.h"
#include <iostream>
#include <string>
#include <codecvt>
#include <assert.h>
#include <stdio.h>
#include <fcntl.h>
#include <random>
#include <stdarg.h>
#include <openssl/bio.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include "llhttp.h"
#include "context.h"

#define DEFAULT_PORT 7000
#define DEFAULT_BACKLOG 128
#define DEFAULT_PEM "localhost.pem"
#define DEFAULT_KEY "localhost.key"

using namespace std;

uv_loop_t *loop;
SSL_CTX *ssl_ctx = NULL;

SSL_CTX *create_context()
{
    const SSL_METHOD *method;
    SSL_CTX *ctx;

    method = TLS_server_method();

    ctx = SSL_CTX_new(method);
    if (ctx == NULL)
    {
        perror("Unable to create SSL context");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    return ctx;
}

void configure_server_context(SSL_CTX *ctx)
{
    /* Set the key and cert */
    if (SSL_CTX_use_certificate_chain_file(ctx, DEFAULT_PEM) <= 0)
    {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
    if (SSL_CTX_use_PrivateKey_file(ctx, DEFAULT_KEY, SSL_FILETYPE_PEM) <= 0)
    {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
}

int main(int argc, const char **argv)
{
    struct sockaddr_in addr;

    ssl_ctx = create_context();

    configure_server_context(ssl_ctx);

    loop = uv_default_loop();

    uv_tcp_t server;
    uv_tcp_init(loop, &server);

    uv_ip4_addr("127.0.0.1", DEFAULT_PORT, &addr);

    uv_tcp_bind(&server, (const struct sockaddr *)&addr, 0);
    server.data = ssl_ctx;
    int r = uv_listen((uv_stream_t *)&server, DEFAULT_BACKLOG, Context::on_uv_new_connection);
    if (r)
    {
        fprintf(stderr, "Listen error %s\n", uv_strerror(r));
        return 1;
    }
    else
    {
        fprintf(stdout, "Listening on port %d\n", DEFAULT_PORT);
    }
    return uv_run(loop, UV_RUN_DEFAULT);
}