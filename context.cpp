#include "context.h"
#include <llhttp.h>
#include <iostream>
#include <map>
#include <algorithm>
#include <cctype>
#include <vector>
#include <ctime>
#include <openssl/bio.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

using namespace std;

namespace {
    string toUpper(string s);
}

void Context::on_uv_read_from_remote(uv_stream_t* client, ssize_t nread, const uv_buf_t* buf) {
    Context* context = (Context*)client->data;
    if (nread > 0) {
        int err = SSL_write(context->clientSSLItem, buf->base, nread);
        if (err < 0) {
            int errCode = SSL_get_error(context->clientSSLItem, err);
            if (errCode == SSL_ERROR_WANT_READ || errCode == SSL_ERROR_WANT_WRITE) {
                // continue
            }
            else {
                if (errCode == SSL_ERROR_ZERO_RETURN) {
                    cout << "err == SSL_ERROR_ZERO_RETURN: unexpected EOF from remote" << endl;
                }
                ssh_shutdown_wrap(context->clientSSLItem);
                closeHandles(context);
                ERR_print_errors_fp(stderr);
            }
        }
        return;
    }
    if (nread < 0) {
        if (nread != UV_EOF)
            fprintf(stderr, "Read error %s\n", uv_err_name(nread));
        closeHandles(context);
    }

    if (buf->base) {
        free(buf->base);
    }
};

void Context::on_uv_write_success(uv_write_t* req, int status) {
    if (status) {
        fprintf(stderr, "Write error %s\n", uv_strerror(status));
    }
    Context* context = (Context*)uv_handle_get_data((uv_handle_t*)req);
    free_write_req(req);
}

void Context::assiateHandles(Context* context) {
    context->clientSSLStreamingHandlePtr = (uv_idle_t*)malloc(sizeof(uv_idle_t));
    uv_handle_set_data((uv_handle_t*)context->clientSSLStreamingHandlePtr, context);
    int err = uv_idle_init(uv_default_loop(), context->clientSSLStreamingHandlePtr);
    err = uv_idle_start(context->clientSSLStreamingHandlePtr, Context::client_idle_ssl_streaming);
    uv_read_start((uv_stream_t*)context->forwardTcpHandlePtr, alloc_buffer, on_uv_read_from_remote);
}

void Context::on_uv_forward_connected(uv_connect_t* req, int status) {
    if (status < 0) {
        fprintf(stderr, "connect failed error %s\n", uv_err_name(status));
        free(req);
        return;
    }

    Context* context = (Context*)req->data;

    string retStr = Context::getConnectSuccessRet();
    string returnStr = "HTTP/1.1 200 Connection established\r\n";
    returnStr += "Proxy-Agent: croxy/0.0.1\r\n";
    returnStr += "\r\n";
    int err = SSL_write(context->clientSSLItem, returnStr.c_str(), returnStr.size());
    if (err < 0) {
        cerr << "SSL_write_error: ";
        ERR_print_errors_fp(stderr);
    }
    else {
        Context::assiateHandles(context);
    }
    free(req);
}

void Context::on_uv_remote_addr_resolved(uv_getaddrinfo_t* resolver, int status, struct addrinfo* res) {
    if (status < 0) {
        fprintf(stderr, "getaddrinfo callback error %s\n", uv_err_name(status));
        return;
    }

    char addr[17] = { '\0' };
    uv_ip4_name((struct sockaddr_in*)res->ai_addr, addr, 16);
    fprintf(stderr, "%s\n", addr);

    Context* context = (Context*)resolver->data;

    uv_connect_t* forwardTcpReqPtr = (uv_connect_t*)malloc(sizeof(uv_connect_t));

    uv_handle_set_data((uv_handle_t*)forwardTcpReqPtr, (void*)context);
    context->forwardTcpHandlePtr = (uv_tcp_t*)malloc(sizeof(uv_tcp_t));
    uv_handle_set_data((uv_handle_t*)context->forwardTcpHandlePtr, (void*)context);
    uv_tcp_init(uv_default_loop(), context->forwardTcpHandlePtr);

    uv_tcp_connect(forwardTcpReqPtr, context->forwardTcpHandlePtr, (const struct sockaddr*)res->ai_addr, on_uv_forward_connected);

    uv_freeaddrinfo(res);
    free(resolver);
}

// ÿ�� fd ׼���ö�ȡʱ������ô˺���
void Context::on_uv_handle_ssl_handshake(uv_poll_t* handle, int status, int events) {
    Context* contextPtr = (Context*)uv_handle_get_data((uv_handle_t*)handle);
    SSL* ssl_item = contextPtr->clientSSLItem;
    int accept_ret = SSL_accept(ssl_item);
    if (accept_ret == 0) {
        ERR_print_errors_fp(stderr);
    }
    // accept_ret == 1��The TLS/SSL handshake was successfully completed
    else if (accept_ret == 1) {
        llhttp_t* parser = &(contextPtr->parser);
        char buf[BUF_LEN];
        memset(buf, 0, BUF_LEN);
        while (true) {
            int read_byte = SSL_read(ssl_item, buf, BUF_LEN - 1);
            if (read_byte > 0) {
                enum llhttp_errno err = llhttp_execute(parser, buf, read_byte);
            }
            else if (read_byte <= 0) {
                int err = SSL_get_error(ssl_item, accept_ret);
                ERR_print_errors_fp(stderr);
                break;
            }
        }
    }
    else if (accept_ret == -1) {
        int err = SSL_get_error(ssl_item, accept_ret);
        if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) {
            // continue handshake
            //std::cout << "ssl continue handshake" << endl;
        }
    }
    else {
        cout << "ssl handshake err" << endl;
        ERR_print_errors_fp(stderr);
    }
}

// callbacks below can return  
// `0` (proceed normally), 
// `-1` (error) or 
// `HPE_PAUSED` (pause the parser):
int Context::on_method_complete(llhttp_t* parser) {
    Context* context = (Context*)parser->data;
    context->method = string(llhttp_method_name((llhttp_method_t)parser->method));
	return 0;
}

int Context::on_message_complete(llhttp_t* parser) {
    cout << "inside on_message_complete" << endl;
    Context* context = (Context*)parser->data;

    if (parser->method == HTTP_CONNECT) {
        uv_getaddrinfo_t* resolver = (uv_getaddrinfo_t*)malloc(sizeof(uv_getaddrinfo_t));
        uv_handle_set_data((uv_handle_t*)resolver, context);
        uv_idle_stop(context->clientSSLHandshakeHandlePtr);

        // �����ѯ remote server ip ������
        int r = uv_getaddrinfo(
            uv_default_loop(),
            resolver,
            Context::on_uv_remote_addr_resolved,
            context->remoteHost.c_str(),
            context->remotePort.c_str(),
            &context->hints
        );

        if (r) {
            fprintf(stderr, "getaddrinfo call error %s\n", uv_err_name(r));
        }
    }
    return 0;
}

int Context::on_header_field_complete(llhttp_t* parser) {
    return 0;
}

int Context::on_headers_complete(llhttp_t* parser) {
    Context* context = (Context*)parser->data;
    context->headersMap = vectorToMap(context->headersVector);
    for (const auto& kv : context->headersMap) {
        cout << kv.first << ": " << kv.second << endl;
    }
    vector<string> splitted;

    splitString(context->headersMap["HOST"], splitted, ":");

    if (splitted.size() > 1) {
        context->remoteHost = splitted[0];
        context->remotePort = splitted[1];
    }
    return 0;
}

int Context::on_header_value_complete(llhttp_t* parser) {
    cout << "inside on_header_value_complete" << endl;
    return 0;
}

// callbacks below can return 
// `0` (proceed normally), 
// `-1` (error) or 
// `HPE_USER` (error from the callback)
int Context::on_header_field(llhttp_t* parser, const char* at, size_t length) {
    Context* contextPtr = (Context* )(parser->data);
    string all(at);
    string key = toUpper(all);
    pair<string, string> headerPair;
    headerPair.first = key.substr(0, length);
    headerPair.second = "";
    contextPtr->headersVector.push_back(headerPair);
    return 0;
}

int Context::on_header_value(llhttp_t* parser, const char* at, size_t length) {
    Context* contextPtr = (Context*)(parser->data);
    string all(at);
    string value = all.substr(0, length);
    auto& v = contextPtr->headersVector;
    (v[v.size() - 1]).second = value;
    return 0;
}

void Context::on_uv_new_connection(uv_stream_t* server, int status){
    if (status < 0)
    {
        fprintf(stderr, "New connection error %s\n", uv_strerror(status));
        // error!
        return;
    }

    uv_loop_t* loop = uv_default_loop();
    SSL_CTX* ssl_ctx = (SSL_CTX*)server->data;

    uv_tcp_t* client = (uv_tcp_t*)malloc(sizeof(uv_tcp_t));
    uv_tcp_init(loop, client);
    // windows��uv_accept �ڲ������� uv__tcp_set_socket ������ accept ���ص�
    // �ļ�����������Ϊ������
    if (uv_accept(server, (uv_stream_t*)client) == 0)
    {
        Context* context = new Context();
        context->clientTcpHandlePtr = client;
        uv_unref((uv_handle_t*)context->clientTcpHandlePtr);

        uv_fileno((uv_handle_t*)context->clientTcpHandlePtr, &context->client_socket);

        context->clientSSLItem = SSL_new(ssl_ctx);
        SSL* ssl_item = context->clientSSLItem;
        int err = SSL_set_fd(context->clientSSLItem, (int)context->client_socket);

        // �� contextItem ������ llhttp �� parser ��������
        context->parser.data = (void*)context;

        context->clientSSLHandshakeHandlePtr = (uv_idle_t*)malloc(sizeof(uv_idle_t));
        uv_handle_set_data((uv_handle_t*)context->clientSSLHandshakeHandlePtr, context);
        err = uv_idle_init(loop, context->clientSSLHandshakeHandlePtr);
        err = uv_idle_start(context->clientSSLHandshakeHandlePtr, Context::client_idle_ssl_handshake);
    }
    else
    {
        uv_close((uv_handle_t*)client, Context::on_uv_handle_closed);
    }
}

string Context::getConnectSuccessRet() {
    return string("HTTP/1.1 200 Connection established\r\nProxy-Agent: proxy/0.0.1\r\n\r\n");
}

void Context::free_write_req(uv_write_t* req) {
    write_req_t* wr = (write_req_t*)req;
    free(wr->buf.base);
    free(wr);
}

void Context::alloc_buffer(uv_handle_t* handle, size_t suggested_size, uv_buf_t* buf) {
    buf->base = (char*)malloc(suggested_size);
    buf->len = suggested_size;
}

map<string, string> Context::vectorToMap(vector<pair<string, string>> v) {
    auto it = v.begin();
    auto end = v.end();
    map<string, string> m;
    while (it != end) {
        m.insert(*it);
        it++;
    }
    return m;
}

void Context::splitString(const string& s, vector<string>& v, const string& delimiter)
{
    string::size_type pos1, pos2;
    pos2 = s.find(delimiter);
    pos1 = 0;
    while (string::npos != pos2)
    {
        v.push_back(s.substr(pos1, pos2 - pos1));

        pos1 = pos2 + delimiter.size();
        pos2 = s.find(delimiter, pos1);
    }
    if (pos1 != s.length())
        v.push_back(s.substr(pos1));
}

void Context::on_uv_handle_closed(uv_handle_t* handle) {
    free(handle);
}

void Context::on_close_client_handle(uv_handle_t* handle) {
    Context* context = (Context*)uv_handle_get_data(handle);
    free(context->clientSSLStreamingHandlePtr);
    context->clientSSLStreamingHandlePtr = nullptr;
    clearAssets(context);
}

void Context::on_close_remote_handle(uv_handle_t* handle) {
    Context* context = (Context*)uv_handle_get_data(handle);
    free(context->forwardTcpHandlePtr);
    context->forwardTcpHandlePtr = nullptr;
    clearAssets(context);
}

void Context::on_close_handshake_handle(uv_handle_t* handle) {
    Context* context = (Context*)uv_handle_get_data(handle);
    free(context->clientSSLHandshakeHandlePtr);
    context->clientSSLHandshakeHandlePtr = nullptr;
    clearAssets(context);
}

void Context::client_idle_ssl_streaming(uv_idle_t* handle) {
    Context* context = (Context*)uv_handle_get_data((uv_handle_t*)handle);

    char* write_buf = (char*)malloc(BUF_LEN);
    int read_byte = SSL_read(context->clientSSLItem, write_buf, BUF_LEN);
    if (read_byte > 0) {
        write_req_t* req = (write_req_t*)malloc(sizeof(write_req_t));
        uv_handle_set_data((uv_handle_t*)req, (void*)context);
        req->buf = uv_buf_init(write_buf, read_byte);
        uv_write((uv_write_t*)req, (uv_stream_t*)context->forwardTcpHandlePtr, &req->buf, 1, on_uv_write_success);
    }
    else {
        int err = SSL_get_error(context->clientSSLItem, read_byte);
        if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) {
            // continue
        }
        else {
            if (err == SSL_ERROR_ZERO_RETURN) {
                cout << "err == SSL_ERROR_ZERO_RETURN: unexpected EOF from client" << endl;
            }
            ssh_shutdown_wrap(context->clientSSLItem);
            closeHandles(context);
        }
        free(write_buf);
    }
}

void Context::closeHandles(Context* context) {
    uv_close((uv_handle_t*)context->clientSSLStreamingHandlePtr, on_close_client_handle);
    uv_close((uv_handle_t*)context->forwardTcpHandlePtr, on_close_remote_handle);
    uv_close((uv_handle_t*)context->clientSSLHandshakeHandlePtr, on_close_handshake_handle);
    if (uv_is_active((uv_handle_t*)context->clientTcpHandlePtr)) {
        uv_close((uv_handle_t*)context->clientTcpHandlePtr, NULL);
    }
    
}

void Context::clearAssets(Context* context) {
    if (
        context->clientSSLStreamingHandlePtr == nullptr &&
        context->clientSSLHandshakeHandlePtr == nullptr &&
        context->forwardTcpHandlePtr == nullptr
    ) {
        if (context->clientSSLItem) {
            cout << "SSL_free ssl" << endl;
            SSL_free(context->clientSSLItem);
            context->clientSSLItem = NULL;
        }

        if (!context->clientTcpHandlePtr) {
            context->clientTcpHandlePtr = nullptr;
        }

        llhttp_t* parser = &context->parser;
        memset(&context->parser, 0, sizeof(&context->parser));

        delete context;
    }
}

void Context::client_idle_ssl_handshake(uv_idle_t* handle) {
    Context* context = (Context*)uv_handle_get_data((uv_handle_t*)handle);
    int accept_ret = SSL_accept(context->clientSSLItem);
    if (accept_ret == 0) {
        ERR_print_errors_fp(stderr);
    }
    // accept_ret == 1 The TLS/SSL handshake was successfully completed
    else if (accept_ret == 1) {
        llhttp_t* parser = &(context->parser);
        char buf[BUF_LEN];
        memset(buf, 0, BUF_LEN);
        while (true) {
            int read_byte = SSL_read(context->clientSSLItem, buf, BUF_LEN - 1);
            if (read_byte > 0) {
                enum llhttp_errno err = llhttp_execute(parser, buf, read_byte);
            }
            else if (read_byte <= 0) {
                int err = SSL_get_error(context->clientSSLItem, accept_ret);
                ERR_print_errors_fp(stderr);
                break;
            }
        }
    }
    else if (accept_ret == -1) {
        int err = SSL_get_error(context->clientSSLItem, accept_ret);
        if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) {
            // continue handshake
            //std::cout << "ssl continue handshake" << endl;
        }
    }
    else {
        cout << "ssl handshake err" << endl;
        ERR_print_errors_fp(stderr);
    }
}

int Context::ssh_shutdown_wrap(SSL* ssl) {
    while (true) {
        int shutdown_res = SSL_shutdown(ssl);
        if (shutdown_res == 0) {
            // not yet success
            int err = SSL_get_error(ssl, shutdown_res);
            if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) {
                continue;
            }
        }
        else if (shutdown_res == 1) {
            // successfully completed
            return 1;
        }
        else if (shutdown_res < 0) {
            ERR_print_errors_fp(stderr);
            return -1;
        }
    }
}

Context::Context() {
    /* Initialize user callbacks and settings */
    llhttp_settings_init(&settings);

    /* Set user callback */
    settings.on_method_complete = Context::on_method_complete;
    settings.on_message_complete = Context::on_message_complete;
    settings.on_header_field_complete = Context::on_header_field_complete;
    settings.on_header_value_complete = Context::on_header_value_complete;
    settings.on_headers_complete = Context::on_headers_complete;
    settings.on_header_field = Context::on_header_field;
    settings.on_header_value = Context::on_header_value;

    /* Initialize the parser */
    llhttp_init(&parser, HTTP_REQUEST, &settings);

    forwardTcpHandlePtr = nullptr;
    clientSSLHandshakeHandlePtr = nullptr;
    clientSSLStreamingHandlePtr = nullptr;
    clientSSLItem = nullptr;
    clientTcpHandlePtr = nullptr;

    hints.ai_family = PF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;
    hints.ai_flags = 0;

}

Context::~Context() {
}

namespace {
    string toUpper(string s) {
        std::transform(s.begin(), s.end(), s.begin(),
            [](unsigned char c) { return std::toupper(c);
        });
        return s;
    }
}