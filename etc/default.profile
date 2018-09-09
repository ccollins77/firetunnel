# Firetunnel default profile

# Tunnel network address, default 10.10.20.0.
netaddr 10.10.20.0

# Tunnel network mask, default 255.255.255.0
netmask 255.255.255.0

# Tunnel default gateway address, default 10.10.20.1
defaultgw 10.10.20.1

# Tunnel default MTU, calculated by the software if not enabled here.
# mtu 1419

# NAT enabled by default.
# nonat

# Default scrambling is enabled.
# noscrambling

# Run the program as a Unix daemon, disabled by default.
# daemonize

# Seccomp enabled by default for parent and child processes.
# noseccomp

# seccomp configuration for parent and child processes if seccomp enabled
seccomp.child    write,read,close,open,openat,writev,select,sendto,recvfrom,socket,connect,fstat,stat,getpid,mmap,munmap,mremap,sigreturn,rt_sigprocmask,exit_group,kill,wait4
seccomp.parent sendto,write,read,close,open,openat,writev,ioctl,socket,connect,fstat,stat,getpid,mmap,munmap,mremap,sigreturn,rt_sigprocmask,exit_group,kill,wait4

#DNS servers - not more than 16 are allowed
# Cloudflare
dns 1.1.1.1
# Quad9
dns 9.9.9.9
# Level 3
dns 4.2.2.1
# Google
dns 8.8.8.8
# OpenDNS
dns 208.67.222.222
# Yandex
dns 77.88.8.8
# DNS.WATCH
dns 84.200.69.80
# Comodo Secure DNS
dns 8.26.56.26
