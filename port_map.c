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

#ifdef WINDOWS
#define LIB_NAME            "miniupnpc.dll"
#endif

#ifdef LINUX
#include <dlfcn.h>
#ifdef MACOSX
#define LIB_NAME            "libminiupnpc.dylib"
#else
#define LIB_NAME            "libminiupnpc.so"
#endif
#endif

struct UPNPDev;
struct UPNPUrls
{
    char *controlURL;
    char *ipcondescURL;
    char *controlURL_CIF;
    char *controlURL_6FC;
    char *rootdescURL;
};
#define MINIUPNPC_URL_MAXSIZE 128
struct IGDdatas_service
{
    char controlurl[MINIUPNPC_URL_MAXSIZE];
    char eventsuburl[MINIUPNPC_URL_MAXSIZE];
    char scpdurl[MINIUPNPC_URL_MAXSIZE];
    char servicetype[MINIUPNPC_URL_MAXSIZE];
};
struct IGDdatas
{
    char cureltname[MINIUPNPC_URL_MAXSIZE];
    char urlbase[MINIUPNPC_URL_MAXSIZE];
    char presentationurl[MINIUPNPC_URL_MAXSIZE];
    int level;
    struct IGDdatas_service CIF;
    struct IGDdatas_service first;
    struct IGDdatas_service second;
    struct IGDdatas_service IPv6FC;
    struct IGDdatas_service tmp;
};
struct UPNPDev *(*upnpDiscover)(int, const char *, const char *, int, int,
    int *);
int (*UPNP_GetValidIGD)(struct UPNPDev *, struct UPNPUrls *, struct IGDdatas *,
    char *, int);
int (*UPNP_GetExternalIPAddress)(const char *, const char *, char *);
int (*UPNP_AddPortMapping)(const char *, const char *, const char *,
    const char *, const char *, const char *, const char *, const char *,
    const char *);

// Load the library.
static bool load_library(void)
{
#ifdef LINUX
    void *lib = dlopen(LIB_NAME, RTLD_LOCAL | RTLD_NOW);
    if (lib == NULL)
        return false;
    upnpDiscover = dlsym(lib, "upnpDiscover");
    UPNP_GetValidIGD = dlsym(lib, "UPNP_GetValidIGD");
    UPNP_GetExternalIPAddress = dlsym(lib, "UPNP_GetExternalIPAddress");
    UPNP_AddPortMapping = dlsym(lib, "UPNP_AddPortMapping");
#endif

#ifdef WINDOWS
    HMODULE lib = LoadLibrary(LIB_NAME);
    if (lib == NULL)
        return false;
    upnpDiscover = (void *)GetProcAddress(lib, "upnpDiscover");
    UPNP_GetValidIGD = (void *)GetProcAddress(lib, "UPNP_GetValidIGD");
    UPNP_GetExternalIPAddress =
        (void *)GetProcAddress(lib, "UPNP_GetExternalIPAddress");
    UPNP_AddPortMapping = (void *)GetProcAddress(lib, "UPNP_AddPortMapping");
#endif
    
    return true;
}

// Attempt to add port mapping.
static void *port_map(void *arg)
{
    const char *reason = "no reason";

    if (!load_library())
    {
        reason = "libminiupnpc not found";
        goto port_map_failed;
    }
    if (upnpDiscover == NULL || UPNP_GetValidIGD == NULL ||
            UPNP_GetExternalIPAddress == NULL || UPNP_AddPortMapping == NULL)
    {
        reason = "incompatible libminiupnpc";
        goto port_map_failed;
    }

    char port_str[8];
    int r = snprintf(port_str, sizeof(port_str)-1, "%u", ntohs(PORT));
    if (r <= 0 || r >= sizeof(port_str)-1)
        fatal("snprintf failed");

    int err = 0;
    struct UPNPDev *dev = upnpDiscover(2000, NULL, NULL, 0, 0, &err);

    char lan_address[64];
    struct UPNPUrls urls;
    struct IGDdatas data;
    err = UPNP_GetValidIGD(dev, &urls, &data, lan_address, sizeof(lan_address));
    if (err != 1)
    {
        reason = "failed to get IGD";
        goto port_map_failed;
    }
    char wan_address[64];
    err = UPNP_GetExternalIPAddress(urls.controlURL, data.first.servicetype,
        wan_address);
    if (err)
    {
        reason = "failed to get IP address";
        goto port_map_failed;
    }
    while (true)
    {
        err = UPNP_AddPortMapping(urls.controlURL,
            data.first.servicetype, port_str, port_str, lan_address,
            "PseudoNode", "TCP", NULL, "0");
        if (err)
        {
            reason = "failed to add port map";
            goto port_map_failed;
        }
        action("add", "port map for %s", port_str);
        msleep(1000*60*20);     // 20 Minutes
    }

    return NULL;

port_map_failed:
    warning("automatic port mapping failed (%s); open port %u for inbound "
        "connections", reason, ntohs(PORT));
    return NULL;
}
