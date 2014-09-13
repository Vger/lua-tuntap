#ifdef __linux__
#define _GNU_SOURCE           /* For memrchr in string.h */
#endif

#include "lua.h"
#include "lauxlib.h"
#include "tuntap.h"

#if defined(__unix__) || (defined(__APPLE__) && defined(__MACH__))
#include <sys/param.h>	      /* MAXPATHLEN, BSD */
#endif

#include <stdbool.h>
#include <string.h>           /* For strncpy, memset, memrchr */
#include <ctype.h>	      /* isdigit */
#include <fcntl.h>            /* For open */
#include <unistd.h>           /* For close */
#include <sys/ioctl.h>        /* For ioctl */
#include <net/if.h>           /* IFF_UP / struct ifreq */

#ifdef BSD
#include <net/if_tun.h>       /* TUNSIFHEAD */
#include <net/if_dl.h>        /* struct sockaddr_dl */
#endif

#ifdef __linux__
#include <errno.h>
#include <linux/if_tun.h>
#include <netpacket/packet.h> /* struct sockaddr_ll */
#endif

#include <ifaddrs.h>          /* getifaddrs */

/* Maximum size of a single buffer for tunnel interface */
#define IFACE_BUFSIZE 65535

#define TUN_METATABLE "tun"

#ifndef MIN
#define MIN(x, y) ((x) < (y) ? x : y)
#endif

static int init_iface(lua_State *L);
static int meth_dirty(lua_State *L);
static int meth_getfd(lua_State *L);
static int meth_gethwaddr(lua_State *L);
static int meth_receive(lua_State *L);
static int meth_send(lua_State *L);
static int meth_close(lua_State *L);
static int meth_settimeout(lua_State *L);
static int meth_up(lua_State *L);

struct utun {
    int fd;
    lua_Number timeout;
    char name[IFNAMSIZ];
};

static luaL_Reg func[] = {
    {"open", init_iface},
    {NULL, NULL}
};

static luaL_Reg meth[] = {
    {"dirty", meth_dirty},
    {"getfd", meth_getfd},
    {"gethwaddr", meth_gethwaddr},
    {"up", meth_up},
    {"receive", meth_receive},
    {"send", meth_send},
    {"close", meth_close},
    {"settimeout", meth_settimeout},
    {NULL, NULL}
};

static int init_iface(lua_State *L)
{
    const char *device_path;
    size_t device_path_len;
    const char *basename;
    struct ifreq ifr;
    bool tap;
    struct utun *obj = NULL;
    int i;

    luaL_checktype(L, 1, LUA_TSTRING);

    device_path = lua_tolstring(L, 1, &device_path_len);
    if (device_path == NULL)
    {
	lua_pushliteral(L, "Internal error: lua_tolstring returns NULL");
	return lua_error(L);
    }
    basename = memrchr(device_path, '/', device_path_len);
    if (basename == NULL)
	basename = device_path;
    else
	basename++;

    if (basename[0] == 't' && basename[1] == 'u' && basename[2] == 'n')
	tap = false;
    else if (basename[0] == 't' && basename[1] == 'a' && basename[2] == 'p')
	tap = true;
    else
    {
	lua_pushnil(L);
	lua_pushliteral(L, "Neither a TUN nor TAP device specified");
	return 2;
    }
    for (i = 3; basename[i] != '\0'; i++)
    {
	if (!isdigit(basename[i]))
	{
	    lua_pushnil(L);
	    lua_pushfstring(L, "The name \"%s\" is invalid.", basename);
	    return 2;
	}
    }
    if (i+1 > sizeof obj->name)
    {
	lua_pushnil(L);
	lua_pushliteral(L, "The interface name is too long.");
	return 2;
    }

    obj = (struct utun *) lua_newuserdata(L, sizeof(struct utun));
    obj->fd = -1;
    obj->timeout = -1;

    memset(&ifr, 0, sizeof ifr);

#ifdef __linux__
    obj->fd = open("/dev/net/tun", O_RDWR);
    if (obj->fd < 0)
    {
	lua_pop(L, 1);
	lua_pushnil(L);
	lua_pushliteral(L, "Could not open clone device \"/dev/net/tun\"");
	return 2;
    }

    ifr.ifr_flags = tap ? IFF_TAP : IFF_TUN;
    ifr.ifr_flags |= IFF_NO_PI;

    if (basename[3] != '\0')
	strncpy(ifr.ifr_name, basename, sizeof(ifr.ifr_name));

    if (ioctl(obj->fd, TUNSETIFF, &ifr) < 0)
    {
	lua_pop(L, 1);
	lua_pushnil(L);
	lua_pushfstring(L, "Failed to configure %s tunnel: %s", basename, strerror(errno));
	goto failed;
    }

    strncpy(obj->name, ifr.ifr_name, sizeof(obj->name));
#endif /* __linux__ */

#ifdef BSD
    obj->fd = open(device_path, O_RDWR);
    if (obj->fd < 0)
    {
	lua_pop(L, 1);
	lua_pushnil(L);
	lua_pushfstring(L, "Could not open device \"%s\"", device_path);
	return 2;
    }

#if defined(TUNSIFHEAD) && defined(MULTIAF)
    if (!tap)
    {
	/* Turn on tunnel headers */
	int flag = 1;
	if (ioctl(obj->fd, TUNSIFHEAD, &flag) < 0)
	{
	    lua_pop(L, 1);
	    lua_pushnil(L);
	    lua_pushliteral(L, "Initializing multi-af mode failed");
	    goto failed;
	}
    }
#endif

    strncpy(obj->name, basename, sizeof(obj->name));

#endif /* BSD */

    luaL_getmetatable(L, TUN_METATABLE);
    lua_setmetatable(L, -2);

    return 1;

failed:
    if (obj && obj->fd >= 0)
	close(obj->fd);
    return 2;
}

static int meth_dirty(lua_State *L)
{
    void *obj = luaL_checkudata(L, 1, TUN_METATABLE);
    (void) obj;
    lua_pushboolean(L, 0);
    return 1;
}

static int meth_getfd(lua_State *L)
{
    struct utun *obj = luaL_checkudata(L, 1, TUN_METATABLE);
    lua_pushnumber(L, obj->fd);
    return 1;
}

/* Get hardware address of tap interface */
static int meth_gethwaddr(lua_State *L)
{
    struct utun *obj = luaL_checkudata(L, 1, TUN_METATABLE);
    struct ifaddrs *ifap = NULL;
    struct ifaddrs *ifa = NULL;
    unsigned char hwaddr[6];
    bool found = false;
    lua_Number v;

    if (obj->fd < 0 || obj->name[0] != 't' || obj->name[1] != 'a' || obj->name[2] != 'p')
    {
	return 0;
    }

    if (getifaddrs(&ifap) < 0)
    {
	lua_pushnil(L);
	lua_pushliteral(L, "Get interface information failed");
	return 2;
    }
    for (ifa = ifap; ifa; ifa = ifa->ifa_next)
    {
#ifdef BSD
	if (ifa->ifa_addr->sa_family == AF_LINK && strcmp(obj->name, ifa->ifa_name) == 0)
	{
	    struct sockaddr_dl *sdl = (struct sockaddr_dl *) ifa->ifa_addr;
	    size_t copylen = sizeof hwaddr;
	    if (sdl->sdl_alen < copylen)
		copylen = sdl->sdl_alen;
	    memcpy(hwaddr, LLADDR(sdl), copylen);
	    found = true;
	    break;
	}
#endif
#ifdef __linux__
	if (ifa->ifa_addr->sa_family == AF_PACKET && strcmp(obj->name, ifa->ifa_name) == 0)
	{
	    struct sockaddr_ll *sll = (struct sockaddr_ll *) ifa->ifa_addr;
	    size_t copylen = sizeof hwaddr;
	    if (sll->sll_halen < copylen)
		copylen = sll->sll_halen;
	    memcpy(hwaddr, sll->sll_addr, copylen);
	    found = true;
	    break;
	}
#endif
    }
    freeifaddrs(ifap);

    if (!found)
	return 0;

    v = hwaddr[0];
    v *= 256;
    v += hwaddr[1];
    v *= 256;
    v += hwaddr[2];
    v *= 256;
    v += hwaddr[3];
    v *= 256;
    v += hwaddr[4];
    v *= 256;
    v += hwaddr[5];
    lua_pushnumber(L, v);

    return 1;
}

static int meth_up(lua_State *L)
{
    struct utun *obj = luaL_checkudata(L, 1, TUN_METATABLE);
    struct ifreq ifr;
    int sock = -1;

    if (obj->fd < 0)
    {
	lua_pushnil(L);
	lua_pushliteral(L, "Tunnel closed");
         goto failed;
    }
    memset(&ifr, 0, sizeof ifr);

    strncpy(ifr.ifr_name, obj->name, sizeof(ifr.ifr_name));
    sock = socket(PF_UNIX, SOCK_STREAM, 0);
    if (sock < 0)
    {
	lua_pushnil(L);
	lua_pushliteral(L, "Socket failed");
	goto failed;
    }

    if (ioctl(sock, SIOCGIFFLAGS, &ifr) < 0)
    {
	lua_pushnil(L);
	lua_pushliteral(L, "Getting up flag on interface failed");
	goto failed;
    }
    if ((ifr.ifr_flags & IFF_UP) == 0)
    {
	ifr.ifr_flags |= IFF_UP;
	if (ioctl(sock, SIOCSIFFLAGS, &ifr) < 0)
	{
	    lua_pushnil(L);
	    lua_pushliteral(L, "Setting up flag on interface failed");
	    goto failed;
	}
    }

    close(sock);
    lua_pushboolean(L, 1);
    return 1;

failed:
    if (sock >= 0)
	close(sock);

    return 2;
}

static int meth_receive(lua_State *L)
{
    struct utun *obj = luaL_checkudata(L, 1, TUN_METATABLE);
    char buffer[IFACE_BUFSIZE];
    size_t target = sizeof(buffer);
    ssize_t readlen;

    if (obj->fd < 0)
    {
	lua_pushnil(L);
	lua_pushliteral(L, "closed");
	return 2;
    }

    if (lua_isnumber(L, 2))
    {
	lua_Number sizespec = lua_tonumber(L, 2);
	if (sizespec < 0)
	    return luaL_argerror(L, 2, "invalid receive pattern");
	target = (size_t) sizespec;
    }
    target = MIN(target, sizeof buffer);

    if (obj->timeout >= 0.0)
    {
	fd_set set;
	struct timeval timeout;

	FD_ZERO(&set);
	FD_SET(obj->fd, &set);

	timeout.tv_sec = (int) obj->timeout;
	timeout.tv_usec = (int)((obj->timeout - timeout.tv_sec) * 1.0e6);

	if (select(obj->fd + 1, &set, NULL, NULL, &timeout) != 1)
	{
	    lua_pushnil(L);
	    lua_pushliteral(L, "timeout");
	    return 2;
	}
    }

    readlen = read(obj->fd, buffer, target);
    if (readlen < 0)
    {
	lua_pushnil(L);
	return 1;
    }
    lua_pushlstring(L, buffer, readlen);
    return 1;
}

static int meth_close(lua_State *L)
{
    struct utun *obj = luaL_checkudata(L, 1, TUN_METATABLE);
    if (obj->fd >= 0)
    {
	close(obj->fd);
	obj->fd = -1;
    }
    return 0;
}

static int meth_send(lua_State *L)
{
    struct utun *obj = luaL_checkudata(L, 1, TUN_METATABLE);
    size_t count = 0;
    const char *data = luaL_checklstring(L, 2, &count);
    ssize_t rc;

    if (obj->fd < 0)
    {
	lua_pushnil(L);
	lua_pushliteral(L, "closed");
	return 2;
    }

    rc = write(obj->fd, data, count);
    if (rc >= 0)
    {
	lua_pushnumber(L, rc);
	return 1;
    }
    lua_pushnil(L);
    return 1;
}

static int meth_settimeout(lua_State *L)
{
    struct utun *obj = luaL_checkudata(L, 1, TUN_METATABLE);
    lua_Number t = luaL_optnumber(L, 2, -1);
    obj->timeout = t;
    lua_pushnumber(L, 1);
    return 1;
}

TUNAPI int luaopen_tuntap(lua_State *L)
{
    /* export functions and leave table on top of the stack */
#if LUA_VERSION_NUM > 501 && !defined(LUA_COMPAT_MODULE)
    lua_newtable(L);
    luaL_setfuncs(L, func, 0);
#else
    luaL_openlib(L, "tun", func, 0);
#endif

    luaL_newmetatable(L, TUN_METATABLE);
    lua_pushliteral(L, "__gc");
    lua_pushcfunction(L, meth_close);
    lua_rawset(L, -3);

    lua_pushliteral(L, "__index");
    lua_newtable(L);

#if LUA_VERSION_NUM > 501 && !defined(LUA_COMPAT_MODULE)
    luaL_setfuncs(L, meth, 0);
#else
    luaL_openlib(L, NULL, meth, 0);
#endif
    lua_rawset(L, -3);
    lua_pop(L, 1);
    return 1;
}
