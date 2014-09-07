#include "lua.h"
#include "lauxlib.h"
#include "tuntap.h"

#include <stdbool.h>
#include <string.h>     /* For strncpy */
#include <fcntl.h>      /* For open */
#include <unistd.h>     /* For close */
#include <libgen.h>     /* For basename_r */
#include <sys/ioctl.h>  /* For ioctl */
#include <net/if.h>     /* IFF_UP / struct ifreq */
#include <net/if_tun.h> /* TUNSIFHEAD */
#include <sys/param.h>  /* MAXPATHLEN */
#include <net/if_dl.h>  /* struct sockaddr_dl */
#include <ifaddrs.h>    /* getifaddrs */

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

struct utun {
    int fd;
    unsigned char hwaddr[6];
};

static luaL_Reg func[] = {
    {"open", init_iface},
    {NULL, NULL}
};

static luaL_Reg meth[] = {
    {"dirty", meth_dirty},
    {"getfd", meth_getfd},
    {"gethwaddr", meth_gethwaddr},
    {"receive", meth_receive},
    {"send", meth_send},
    {"close", meth_close},
    {NULL, NULL}
};

static int init_iface(lua_State *L)
{
    const char *iface_path = luaL_checkstring(L, 1);
    struct ifreq ifr;
    char tun_name[MAXPATHLEN+1];
    bool tap;
    struct utun template = {-1, {0}};
    int sock = -1;
    int rc = 0;
    struct utun *obj = NULL;

    basename_r(iface_path, tun_name);
    if (tun_name[0] == 't' && tun_name[1] == 'u' && tun_name[2] == 'n')
	tap = false;
    else if (tun_name[0] == 't' && tun_name[1] == 'a' && tun_name[2] == 'p')
	tap = true;
    else
    {
	lua_pushnil(L);
	lua_pushliteral(L, "Neither a TUN nor TAP device specified");
	return 2;
    }

    template.fd = open(iface_path, O_RDWR);
    if (template.fd < 0)
    {
	lua_pushnil(L);
	lua_pushfstring(L, "Could not open device \"%s\"", iface_path);
	return 2;
    }

    if (!tap)
    {
	/* Turn on tunnel headers */
	int flag = 1;
	if (ioctl(template.fd, TUNSIFHEAD, &flag) < 0)
	{
	    lua_pushnil(L);
	    lua_pushliteral(L, "Initializing multi-af mode failed");
	    goto failed;
	}
    }

    strncpy(ifr.ifr_name, tun_name, sizeof(ifr.ifr_name));
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

    if (tap)
    {
	/* Get hardware address of tap interface */
	struct ifaddrs *ifap = NULL;
	struct ifaddrs *ifa = NULL;

	if (getifaddrs(&ifap) < 0)
	{
	    lua_pushnil(L);
	    lua_pushliteral(L, "Get interface information failed");
	    goto failed;
	}
	for (ifa = ifap; ifa; ifa = ifa->ifa_next)
	{
	    if (ifa->ifa_addr->sa_family == AF_LINK && strcmp(tun_name, ifa->ifa_name) == 0)
	    {
		struct sockaddr_dl *sdl = (struct sockaddr_dl *) ifa->ifa_addr;
		size_t copylen = sizeof template.hwaddr;
		if (sdl->sdl_alen < copylen)
		    copylen = sdl->sdl_alen;
		memcpy(&(template.hwaddr), LLADDR(sdl), copylen);
		break;
	    }
	}
	freeifaddrs(ifap);
    }

    close(sock);

    obj = (struct utun *) lua_newuserdata(L, sizeof(struct utun));
    memcpy(obj, &template, sizeof template);
    luaL_getmetatable(L, TUN_METATABLE);
    lua_setmetatable(L, -2);

    return 1;

failed:
    rc = 2;
    /* Fall-through to failed */

    if (template.fd >= 0)
	close(template.fd);
    if (sock >= 0)
	close(sock);
    return rc;
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

static int meth_gethwaddr(lua_State *L)
{
    struct utun *obj = luaL_checkudata(L, 1, TUN_METATABLE);
    lua_Number v = obj->hwaddr[0];
    v *= 256;
    v += obj->hwaddr[1];
    v *= 256;
    v += obj->hwaddr[2];
    v *= 256;
    v += obj->hwaddr[3];
    v *= 256;
    v += obj->hwaddr[4];
    v *= 256;
    v += obj->hwaddr[5];
    lua_pushnumber(L, v);
    return 1;
}

static int meth_receive(lua_State *L)
{
    struct utun *obj = luaL_checkudata(L, 1, TUN_METATABLE);
    char buffer[IFACE_BUFSIZE];
    size_t target = sizeof(buffer);
    ssize_t readlen;

    if(lua_isnumber(L, 2))
    {
	lua_Number sizespec = lua_tonumber(L, 2);
	if (sizespec < 0)
	    return luaL_argerror(L, 2, "invalid receive pattern");
	target = (size_t) sizespec;
    }
    target = MIN(target, sizeof buffer);
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

    rc = write(obj->fd, data, count);
    if (rc >= 0)
    {
	lua_pushnumber(L, rc);
	return 1;
    }
    lua_pushnil(L);
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
