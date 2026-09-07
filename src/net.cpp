#include "net.hpp"
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <unistd.h>

int tcp_listen(int port) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return -1;
    int yes = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);   // loopback only, never expose this
    addr.sin_port = htons(port);

    if (bind(fd, (sockaddr*)&addr, sizeof(addr)) < 0) { close(fd); return -1; }
    if (listen(fd, 16) < 0) { close(fd); return -1; }
    return fd;
}

int tcp_accept(int listen_fd) {
    int fd = accept(listen_fd, nullptr, nullptr);
    if (fd >= 0) {
        int yes = 1;
        // Turn off Nagle — I'm sending tiny one-line messages and don't want
        // them buffered, which would wreck the timing measurement.
        setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &yes, sizeof(yes));
    }
    return fd;
}

int tcp_connect(const char* host, int port) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return -1;

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    if (inet_pton(AF_INET, host, &addr.sin_addr) <= 0) { close(fd); return -1; }

    if (connect(fd, (sockaddr*)&addr, sizeof(addr)) < 0) { close(fd); return -1; }
    int yes = 1;
    setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &yes, sizeof(yes));
    return fd;
}

bool send_line(int fd, const std::string& line) {
    std::string buf = line;
    buf.push_back('\n');
    size_t sent = 0;
    while (sent < buf.size()) {                       // write() can be partial
        ssize_t n = write(fd, buf.data() + sent, buf.size() - sent);
        if (n <= 0) return false;
        sent += (size_t)n;
    }
    return true;
}

bool recv_line(int fd, std::string& out) {
    out.clear();
    char ch;
    while (true) {
        ssize_t n = read(fd, &ch, 1);                 // byte at a time is fine here
        if (n <= 0) return false;
        if (ch == '\n') return true;
        out.push_back(ch);
        if (out.size() > (1u << 20)) return false;    // don't let junk grow forever
    }
}
