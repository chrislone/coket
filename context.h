#include "uv.h"
#include "llhttp.h"
#include <string>
#include <map>
#include <vector>
#include <openssl/ssl.h>

using namespace std;

#define RET_HTTP_HEADERS "HTTP/1.1 200 OK\r\nServer: Apache\r\nContent-Length: 0\r\n\r\n"
#define BUF_LEN 2048

class Context {
public:
    typedef struct {
        uv_write_t req;
        uv_buf_t buf;
    } write_req_t;

    Context();
    ~Context();
    string method;
    string url;
    string status;
    string protocol;
    string version;
    string remotePort;
    string remoteHost;
    map<string, string> headersMap;
    vector<pair<string, string>> headersVector;
    llhttp_t parser;
    llhttp_settings_t settings;

    uv_getaddrinfo_t resolver;
    struct addrinfo hints;

    SSL* clientSSLItem;

    uv_os_fd_t client_socket;
    uv_tcp_t* clientTcpHandlePtr;
    uv_tcp_t* forwardTcpHandlePtr;

    uv_idle_t* clientSSLHandshakeHandlePtr;
    uv_idle_t* clientSSLStreamingHandlePtr;

    // static callbacks
    static int on_method_complete(llhttp_t* parser);
    static int on_message_complete(llhttp_t* parser);
    static int on_header_field_complete(llhttp_t* parser);
    static int on_header_value_complete(llhttp_t* parser);
    static int on_headers_complete(llhttp_t* parser);
    static int on_header_field(llhttp_t* parser, const char* at, size_t length);
    static int on_header_value(llhttp_t* parser, const char* at, size_t length);
    static void on_uv_new_connection(uv_stream_t*, int);
    static void on_uv_remote_addr_resolved(uv_getaddrinfo_t*, int, struct addrinfo*);
    static void on_uv_forward_connected(uv_connect_t*, int);
    static void free_write_req(uv_write_t*);
    // �������� handle����������
    static void assiateHandles(Context*);
    static void on_uv_read_from_remote(uv_stream_t*, ssize_t, const uv_buf_t*);
    static void alloc_buffer(uv_handle_t*, size_t, uv_buf_t*);
    static void on_uv_write_success(uv_write_t*, int);
    static void on_uv_handle_ssl_handshake(uv_poll_t*, int, int);
    static void on_uv_handle_closed(uv_handle_t*);
    static string getConnectSuccessRet();
    static map<string, string> vectorToMap(vector<pair<string, string>> v);
    static void splitString(const string& s, vector<string>& v, const string& c);
    static void client_idle_ssl_handshake(uv_idle_t*);
    static void client_idle_ssl_streaming(uv_idle_t*);
    static void closeHandles(Context*);
    static void clearAssets(Context*);
    static int ssh_shutdown_wrap(SSL* ssl);
    static void on_close_client_handle(uv_handle_t*);
    static void on_close_remote_handle(uv_handle_t*);
    static void on_close_handshake_handle(uv_handle_t*);
};

