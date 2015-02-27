/*
 * PseudoNode
 * Copyright (c) 2015 the copyright holders
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 * 
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 * DEALINGS IN THE SOFTWARE.
 */

// Linux cruft:

#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/mman.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <pwd.h>
#include <pthread.h>

#ifdef MACOSX
#define s6_addr16       __u6_addr.__u6_addr16
#define MSG_NOSIGNAL    0
#define MAP_ANONYMOUS   MAP_ANON
#endif

static bool use_color = false;

#define color_clear(stream)         if (use_color) fputs("\33[0m", stream)
#define color_error(stream)         if (use_color) fputs("\33[31m", stream)
#define color_warning(stream)       if (use_color) fputs("\33[33m", stream)
#define color_log(stream)           if (use_color) fputs("\33[32m", stream)

static bool system_init(void)
{
    use_color = isatty(1);          // stdout
    return true;
}

#define get_error()                 strerror(errno)

static bool rand_init(uint64_t *r)
{
    FILE *stream = fopen("/dev/urandom", "r");
    if (stream == NULL)
        return false;
    bool ok = (fread(r, sizeof(uint64_t), 2, stream) == 2);
    fclose(stream);
    return ok;
}

typedef pthread_mutex_t mutex;

static inline void mutex_init(mutex *m)
{
    int res = pthread_mutex_init(m, NULL);
    assert(res == 0);
}

static inline void mutex_free(mutex *m)
{
    int res = pthread_mutex_destroy(m);
    assert(res == 0);
}

static inline void mutex_lock(mutex *m)
{
    int res = pthread_mutex_lock(m);
    assert(res == 0);
}

static inline void mutex_unlock(mutex *m)
{
    int res = pthread_mutex_unlock(m);
    assert(res == 0);
}

static inline void msleep(size_t ms)
{
    usleep(ms * 1000);
}

// Implementation of Windows-style events in pthreads:
struct event
{
    pthread_mutex_t mutex;
    pthread_cond_t cond;
    bool set;
};
typedef struct event event;

static void event_init(event *e)
{
    mutex_init(&e->mutex);
    int res;
    pthread_condattr_t attr;
    pthread_condattr_init(&attr);
#ifndef MACOSX
    res = pthread_condattr_setclock(&attr, CLOCK_MONOTONIC);
    assert(res == 0);
#endif
    res = pthread_cond_init(&e->cond, &attr);
    assert(res == 0);
    e->set = false;
}

static bool event_wait(event *e)
{
    struct timespec ts;
#ifndef MACOSX
    clock_gettime(CLOCK_MONOTONIC, &ts);
#else
    struct timeval tv;
    int res = gettimeofday(&tv, NULL);
    assert(res == 0);
    ts.tv_sec = tv.tv_sec;
    ts.tv_nsec = 1000 * tv.tv_usec;
#endif
    ts.tv_nsec += rand64() % 1000000000;
    ts.tv_sec += 1 + ts.tv_nsec / 1000000000;
    ts.tv_nsec = ts.tv_nsec % 1000000000;
    mutex_lock(&e->mutex);
    while (!e->set)
    {
        int res = pthread_cond_timedwait(&e->cond, &e->mutex, &ts);
        if (res == ETIMEDOUT)
        {
            mutex_unlock(&e->mutex);
            return false;
        }
    }
    e->set = false;
    mutex_unlock(&e->mutex);
    return true;
}

static void event_set(event *e)
{
    mutex_lock(&e->mutex);
    e->set = true;
    mutex_unlock(&e->mutex);
    int res = pthread_cond_signal(&e->cond);
    assert(res == 0);
}

static inline void event_free(event *e)
{
    mutex_free(&e->mutex);
    int res = pthread_cond_destroy(&e->cond);
    assert(res == 0);
}

#define ref(addr)               \
    __sync_fetch_and_add((addr), 1)
#define deref(addr)             \
    __sync_fetch_and_sub((addr), 1)

static bool spawn_thread(void *(f)(void *), void *arg)
{
    pthread_t thread;
    int res = pthread_create(&thread, NULL, f, (void *)arg);
    if (res != 0)
        return false;
    res = pthread_detach(thread);
    assert(res == 0);
    return true;
}

typedef int sock;
#define INVALID_SOCKET          (-1)

static sock socket_open(void)
{
    sock s = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP);
    if (s < 0)
        return INVALID_SOCKET;
    int on = 1;
    setsockopt(s, SOL_SOCKET, SO_REUSEADDR, (char *)&on, sizeof(on));
    setsockopt(s, IPPROTO_TCP, TCP_NODELAY, (char *)&on, sizeof(on));
    return s;
}

static bool socket_bind(sock s, uint16_t port)
{
    struct sockaddr_in6 sockaddr;
    memset(&sockaddr, 0, sizeof(sockaddr));
    sockaddr.sin6_family = AF_INET6;
    sockaddr.sin6_port   = port;
    if (bind(s, (struct sockaddr *)&sockaddr, sizeof(sockaddr)) != 0)
        return false;
    return true;
}

static bool socket_listen(sock s)
{
    return (listen(s, 4) == 0);
}

static sock socket_accept(sock s, struct in6_addr *addr)
{
    socklen_t len = sizeof(struct sockaddr_in6);
    struct sockaddr_in6 sockaddr;
    int s1 = accept(s, (struct sockaddr *)&sockaddr, &len);
    if (s1 < 0)
        return s1;
    *addr = sockaddr.sin6_addr;
    return s1;
}

static bool socket_connect(sock s, struct in6_addr addr)
{
    struct sockaddr_in6 sockaddr;
    memset(&sockaddr, 0, sizeof(sockaddr));
    sockaddr.sin6_family = AF_INET6;
    sockaddr.sin6_port = PORT;
    sockaddr.sin6_addr = addr;
    int flags = fcntl(s, F_GETFL, 0);
    if (flags < 0 || fcntl(s, F_SETFL, (flags | O_NONBLOCK)) != 0)
        return false;
    if (connect(s, (struct sockaddr *)&sockaddr, sizeof(sockaddr)) < 0 &&
            errno != EINPROGRESS)
        return false;
    if (fcntl(s, F_SETFL, flags) != 0)
        return false;
    struct timeval tv;
    tv.tv_sec = 5;
    tv.tv_usec = rand64() % 1000000;
    fd_set fds;
    FD_ZERO(&fds);
    FD_SET(s, &fds);
    int r = select(s+1, NULL, &fds, NULL, &tv);
    if (r == 0)
        errno = ETIMEDOUT;
    return (r > 0);
}

static ssize_t socket_recv(sock s, void *buf, size_t len, bool *timeout)
{
    *timeout = false;
    struct timeval tv;
    tv.tv_sec = 1;
    tv.tv_usec = rand64() % 1000000;
    fd_set fds;
    FD_ZERO(&fds);
    FD_SET(s, &fds);
    int r = select(s+1, &fds, NULL, &fds, &tv);
    if (r > 0)
        return recv(s, buf, len, MSG_DONTWAIT);
    if (r == 0)
    {
        *timeout = true;
        return 0;
    }
    return -1;
}

static ssize_t socket_send(sock s, void *buf, size_t len)
{
    for (size_t i = 0; i < len; )
    {
        int r = send(s, buf+i, len-i, MSG_NOSIGNAL);
        if (r <= 0)
            return r;
        i += r;
    }
    return len;
}

static void socket_close(sock s)
{
    shutdown(s, SHUT_RDWR);
    close(s);
}

static void server(void)
{
    daemon(1, 0);

    struct passwd *entry = getpwnam("nobody");
    if (entry == NULL)
        return;
    setgid(entry->pw_gid);
    setuid(entry->pw_uid);
}

static void *system_alloc(size_t size)
{
    size_t pagesize = sysconf(_SC_PAGESIZE);
    size = (((size-1) / pagesize) + 1) * pagesize;
    void *ptr = mmap(NULL, size, PROT_READ | PROT_WRITE,
        MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE, -1, 0);
    if (ptr == MAP_FAILED)
        return NULL;
    return ptr;
}

static void system_free(size_t size, void *ptr)
{
    size_t pagesize = sysconf(_SC_PAGESIZE);
    size = (((size-1) / pagesize) + 1) * pagesize;
    int res = munmap(ptr, size);
    assert(res == 0);
}

