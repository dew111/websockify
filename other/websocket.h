#ifndef WINCE
#  include <openssl/ssl.h>
#else
#  include <support_ce.h>
#endif

typedef struct {
    int      sockfd;
    void    *ssl_ctx;
    void    *ssl;
} ws_ctx_t;

typedef struct {
    int verbose;
    char listen_host[256];
    int listen_port;
    void (*handler)(ws_ctx_t*, bool);
    int handler_id;
    char *cert;
    char *key;
    int ssl_only;
    int daemon;
} settings_t;

typedef struct {
    char path[1024+1];
    char host[1024+1];
    char origin[1024+1];
    char key1[1024+1];
    char key2[1024+1];
    char key3[8+1];
    char version[10];
    char connection[1024+1];
    char upgrade[1024+1];
} headers_t;


ssize_t ws_recv(ws_ctx_t *ctx, void *buf, size_t len);

ssize_t ws_send(ws_ctx_t *ctx, const void *buf, size_t len);

void traffic(char * token);
int encode_hixie(u_char const *src, size_t srclength, char *target, size_t targsize);
int decode_hixie(char *src, size_t srclength, u_char *target, size_t targsize);
int encode_hybi(u_char const *src, size_t srclength, char *target, size_t targsize, char opcode);
int decode_hybi(char *src, size_t srclength, u_char *target, size_t targsize);
int resolve_host(struct in_addr *sin_addr, const char *hostname);
void start_server();
void handlerThread(int csock);

/* base64.c declarations */
//int b64_ntop(u_char const *src, size_t srclength, char *target, size_t targsize);
//int b64_pton(char const *src, u_char *target, size_t targsize);

#define gen_handler_msg(stream, ...) \
    if ( settings.daemon) { \
        fprintf(stream, "  %d: ", settings.handler_id); \
        fprintf(stream, __VA_ARGS__); \
    }

#define handler_msg(...) gen_handler_msg(stdout, __VA_ARGS__);
#define handler_emsg(...) gen_handler_msg(stderr, __VA_ARGS__);

