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

// Windows cruft:

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>

extern const char *inet_ntop(int af, const void *src, char *dst,
    socklen_t size);
extern int inet_pton(int af, const char *src, void *dst);
extern errno_t rand_s(unsigned int* r);

#define IPV6_V6ONLY         27      // Missing def for MinGW.

#define STDERR              GetStdHandle(STD_ERROR_HANDLE)
#define color_clear(_)      SetConsoleTextAttribute(STDERR, FOREGROUND_RED | \
                                FOREGROUND_GREEN | FOREGROUND_BLUE)
#define color_error(_)      SetConsoleTextAttribute(STDERR, FOREGROUND_RED)
#define color_warning(_)    SetConsoleTextAttribute(STDERR, FOREGROUND_RED | \
                                FOREGROUND_GREEN)
#define color_log(_)        SetConsoleTextAttribute(STDERR, FOREGROUND_GREEN)

static DWORD err_idx;
#define MAX_ERROR   BUFSIZ

static bool system_init(void)
{
    static WSADATA wsa_data;
    WSAStartup(MAKEWORD(2, 2), &wsa_data);
    err_idx = TlsAlloc();
    if (err_idx == TLS_OUT_OF_INDEXES)
        return false;
    return true;
}

static const char *get_error(void)
{
    DWORD err = GetLastError();
    if (err == 0)
        err = WSAGetLastError();
    char *err_str = (char *)TlsGetValue(err_idx);
    if (err_str == NULL)
    {
        err_str = (char *)malloc((MAX_ERROR+1)*sizeof(char));
        assert(err_str != NULL);
        BOOL ok = TlsSetValue(err_idx, err_str);
        assert(ok);
    }
    DWORD len = FormatMessageA(FORMAT_MESSAGE_FROM_SYSTEM, 0, err, 0, err_str,
        MAX_ERROR, 0);
    if (len == 0 || len > MAX_ERROR-1)
        return "(failed to format error message)";
    err_str[len-1] = '\0';
    SetLastError(0);
    WSASetLastError(0);
    return err_str;
}

static bool rand_init(uint64_t *r)
{
    uint32_t r32[4];
    if (rand_s(r32) != 0 || rand_s(r32+1) != 0 || rand_s(r32+2) != 0 ||
            rand_s(r32+3) != 0)
        return false;
    memcpy(r, r32, sizeof(r32));
    return true;
}

typedef HANDLE mutex;

static inline void mutex_init(mutex *m)
{
    *m = CreateMutex(NULL, FALSE, NULL);
    assert(*m != NULL);
}

static inline void mutex_free(mutex *m)
{
    BOOL res = CloseHandle(*m);
    assert(res);
}

static inline void mutex_lock(mutex *m)
{
    DWORD res = WaitForSingleObject(*m, INFINITE);
    assert(res == WAIT_OBJECT_0);
}

static inline void mutex_unlock(mutex *m)
{
    BOOL res = ReleaseMutex(*m);
    assert(res);
}

static inline void msleep(size_t ms)
{
    Sleep(ms);
}

typedef HANDLE event;

static inline void event_init(event *e)
{
    *e = CreateEvent(NULL, FALSE, FALSE, NULL);
    assert(*e != NULL);
}

static bool event_wait(event *e)
{
    DWORD i = WaitForSingleObject(*e, 1000 + rand64() % 1000);
    if (i == WAIT_TIMEOUT)
        return false;
    assert(i == WAIT_OBJECT_0);
    return true;
}

static inline void event_set(event *e)
{
    BOOL res = SetEvent(*e);
    assert(res);
}

static inline void event_free(event *e)
{
    CloseHandle(*e);
}

#define ref(addr)               \
    __sync_fetch_and_add((addr), 1)
#define deref(addr)             \
    __sync_fetch_and_sub((addr), 1)

static bool spawn_thread(void *(f)(void *), void *arg)
{
    HANDLE thread = CreateThread(NULL, 1, (LPTHREAD_START_ROUTINE)f,
        (LPVOID)arg, 0, NULL);
    return (thread != NULL);
}

typedef SOCKET sock;
typedef uint16_t in_port_t;

static sock socket_open(bool nonblock)
{
    sock s = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP);
    if (s == INVALID_SOCKET)
        return INVALID_SOCKET;
    unsigned off = 0;
    if (setsockopt(s, IPPROTO_IPV6, IPV6_V6ONLY, (char *)&off,
            sizeof(off)) != 0)
    {
        closesocket(s);
        return INVALID_SOCKET;
    }
    unsigned on = 1;
    setsockopt(s, SOL_SOCKET, SO_REUSEADDR, (char *)&on, sizeof(on));
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
    unsigned long on = 1;
    if (ioctlsocket(s, FIONBIO, &on) != 0)
        return false;
    if (connect(s, (struct sockaddr *)&sockaddr, sizeof(sockaddr)) != 0 &&
            WSAGetLastError() != WSAEWOULDBLOCK)
        return false;
    unsigned long off = 0;
    if (ioctlsocket(s, FIONBIO, &off) != 0)
        return false;

    struct timeval tv;
    tv.tv_sec = 5;
    tv.tv_usec = rand64() % 1000000;
    fd_set fds;
    FD_ZERO(&fds);
    FD_SET(s, &fds);
    int r = select(s+1, NULL, &fds, NULL, &tv);
    if (r == 0)
        WSASetLastError(WSAETIMEDOUT);
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
        return recv(s, buf, len, 0);
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
        int r = send(s, buf+i, len-i, 0);
        if (r <= 0)
            return r;
        i += r;
    }
    return len;
}

static void socket_close(sock s)
{
    shutdown(s, SD_BOTH);
    closesocket(s);
}

#define s6_addr16  u.Word

static void server(void)
{
    // NYI
}

static void *system_alloc(size_t size)
{
    return VirtualAlloc(NULL, size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
}

static void system_free(size_t size, void *ptr)
{
    bool res = VirtualFree(ptr, 0, MEM_RELEASE);
    assert(res);
}

