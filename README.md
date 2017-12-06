# ipvssync
IPVS connection sync command

```
$ git clone https://github.com/albatross0/ipvssync
$ cd ipvssync
$ gcc -g -Wall -lnl-3 -o ipvssync libipvs/libipvs.c ipvssync.c
$ ./ipvssync -h
Usage: ipvssync [-d] [-h] [-v] [-f -i ifname -n syncid]
   -d: enable debug messages
   -h: show this message
   -v: print version
   -f: send sync message even if master daemon is not running
   -i ifname: multicast interface name
   -n syncid: id of sync daemon
```
