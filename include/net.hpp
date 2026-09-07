#pragma once
#include <string>

// Tiny blocking TCP layer. Messages are one line of hex terminated by '\n', so
// I can also poke the server by hand with netcat while debugging.

int  tcp_listen(int port);                      // listening fd, or -1
int  tcp_accept(int listen_fd);                 // connection fd, or -1
int  tcp_connect(const char* host, int port);   // client fd, or -1

bool send_line(int fd, const std::string& line);  // appends the '\n'
bool recv_line(int fd, std::string& out);         // reads up to the '\n'
