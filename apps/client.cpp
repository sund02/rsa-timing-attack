// Remote timing probe. Hammers the oracle with the same ciphertext and records
// round-trip latency. I report the minimum and a few low percentiles: jitter
// only ever ADDS delay, so the min RTT is the cleanest estimate of the server's
// real compute time. Standard trick for remote timing.
//
//   ./client --port 9000 --reps 3000
//
// Aim it at a --vulnerable server, then a --secure one on the same seed, and
// compare the minimums.

#include "rsa.hpp"
#include "net.hpp"
#include <algorithm>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>
#include <unistd.h>

using namespace std::chrono;

int main(int argc, char** argv) {
    int port = 9000, reps = 2000;
    const char* host = "127.0.0.1";
    const char* csv = nullptr;

    for (int i = 1; i < argc; ++i) {
        if      (!strcmp(argv[i], "--port") && i+1 < argc) port = atoi(argv[++i]);
        else if (!strcmp(argv[i], "--reps") && i+1 < argc) reps = atoi(argv[++i]);
        else if (!strcmp(argv[i], "--host") && i+1 < argc) host = argv[++i];
        else if (!strcmp(argv[i], "--csv")  && i+1 < argc) csv  = argv[++i];
    }

    int fd = tcp_connect(host, port);
    if (fd < 0) { fprintf(stderr, "connect failed\n"); return 1; }

    // One fixed pseudo-random ciphertext, same every run so results compare.
    gmp_randstate_t rng; gmp_randinit_mt(rng); gmp_randseed_ui(rng, 42);
    mpz_t c; mpz_init(c);
    mpz_urandomb(c, rng, 900);
    std::string payload = mpz_to_hex(c);

    std::vector<long long> samples;
    samples.reserve(reps);
    std::string resp;

    for (int i = 0; i < 50; ++i) { send_line(fd, payload); recv_line(fd, resp); } // warm up

    for (int i = 0; i < reps; ++i) {
        auto t0 = steady_clock::now();
        if (!send_line(fd, payload) || !recv_line(fd, resp)) { fprintf(stderr, "io error\n"); return 1; }
        auto t1 = steady_clock::now();
        samples.push_back(duration_cast<nanoseconds>(t1 - t0).count());
    }
    close(fd);

    std::sort(samples.begin(), samples.end());
    auto pct = [&](double p){ return samples[(size_t)(p * (samples.size() - 1))]; };

    printf("reps          : %d\n", reps);
    printf("min   RTT (us): %.2f\n", samples.front() / 1000.0);
    printf("p1    RTT (us): %.2f\n", pct(0.01) / 1000.0);
    printf("p10   RTT (us): %.2f\n", pct(0.10) / 1000.0);
    printf("median RTT(us): %.2f\n", pct(0.50) / 1000.0);

    if (csv) {   // dump raw samples if I want to look at the distribution later
        FILE* f = fopen(csv, "w");
        if (f) { fprintf(f, "rtt_ns\n"); for (auto s : samples) fprintf(f, "%lld\n", s); fclose(f);
                 fprintf(stderr, "wrote %s\n", csv); }
    }
    mpz_clear(c);
    return 0;
}
