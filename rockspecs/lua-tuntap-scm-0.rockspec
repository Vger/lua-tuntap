package = "lua-tuntap"
version = "scm-0"
source = {
   url = "git://github.com/Vger/lua-tuntap.git",
}
description = {
   summary = "Access to tun/tap interfaces.",
   homepage = "https://github.com/Vger/lua-tuntap",
   license = "MIT/X11",
}
dependencies = {
   "lua >= 5.1",
}

build = {
  type = "builtin",
  modules = {
    tuntap = "src/tuntap.c",
  },
}
