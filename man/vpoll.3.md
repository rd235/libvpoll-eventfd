<!--
.\" Copyright (C) 2019 VirtualSquare. Project Leader: Renzo Davoli
.\"
.\" This is free documentation; you can redistribute it and/or
.\" modify it under the terms of the GNU General Public License,
.\" as published by the Free Software Foundation, either version 2
.\" of the License, or (at your option) any later version.
.\"
.\" The GNU General Public License's references to "object code"
.\" and "executables" are to be interpreted as the output of any
.\" document formatting or typesetting system, including
.\" intermediate and printed output.
.\"
.\" This manual is distributed in the hope that it will be useful,
.\" but WITHOUT ANY WARRANTY; without even the implied warranty of
.\" MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
.\" GNU General Public License for more details.
.\"
.\" You should have received a copy of the GNU General Public
.\" License along with this manual; if not, write to the Free
.\" Software Foundation, Inc., 51 Franklin St, Fifth Floor, Boston,
.\" MA 02110-1301 USA.
.\"
-->

# NAME

vpoll_create, vpoll_ctl, vpoll_close - generate synthetic events for poll/select/ppoll/pselect/epoll

# SYNOPSIS

`#include *vpoll.h*`

`int vpoll_create(uint32_t ` _init_events_`, int ` _flags_`);`

`int vpoll_ctl(int ` _fd_`, int ` _op_`, uint32_t ` _events_`);`

`int vpoll_close(int ` _fd_`);`

# DESCRIPTION

This library permits one to create a vpoll file descriptor "vpollfd" that can be used in
poll/select/ppoll/pselect/epoll(2) system calls.
The events reported by a can be controlled by `vpoll_ctl`. `vpoll` encodes the events using the same flags
EPOLL* defined in `epoll_ctl(2)`.

The library uses the vpoll extension for eventfd if the kernel provides it or the vpoll device
implemented by the vpoll kernel module.
When neither of the kernel supports are available the libvpoll library (partially)
emulates the vpoll feature using socketpair(2). This emulation supports only `EPOLLIN`, `EPOLLOUT` flags and a non standard
version of EPOLLHUP/EPOLLRDHUP.

  `vpoll_create`
: This function creates a "vpollfd". The argument _init_events_ is used to set the initial state of events.
: The following value can be included in _flags_:

  ` `
: `FD_CLOEXEC`:
: Set the close-on-exec flag on the new file descriptor.  See the description of the O_CLOEXEC flag in open(2) for reasons why this may be useful.
: 

  `vpoll_ctl`
: This function changes the set of pending events reported by a "vpollfd".
: The argument _op_ can take the following values:

  ` `
: `VPOLL_CTL_ADDEVENTS`:
: the events set in the argument _events_ are added to the set of pending events.

  ` `
: `VPOLL_CTL_DELEVENTS`:
: the events set in the argument _events_ are deleted from the set of pending events.

  ` `
: `VPOLL_CTL_SETEVENTS`:
: the value of the argument _events_ is assigned to the set of pending events.
: 

  `vpoll_close`
: This function closes the vpoll file descritor.

# RETURN VALUE

`vpoll_create` returns the new file descriptor, or -1  if an error occurred 
(in which case, errno is set appropriately)

`vpoll_ctl` and `vpoll_close` return zero in case of success. On error, -1 is returned, 
and  errno  is set appropriately.

# EXAMPLE

```
#define _GNU_SOURCE
#include *stdio.h*
#include *stdlib.h*
#include *unistd.h*
#include *fcntl.h*
#include *errno.h*
#include *sys/epoll.h*
#include *vpoll.h*

int main(int argc, char *argv[]) {
  int vpollfd = vpoll_create(0, FD_CLOEXEC);
  int epfd = epoll_create1(EPOLL_CLOEXEC);
  struct epoll_event reqevents={EPOLLIN | EPOLLRDHUP | EPOLLERR |
      EPOLLOUT | EPOLLHUP | EPOLLPRI};
  epoll_ctl(epfd,  EPOLL_CTL_ADD, vpollfd, &reqevents);
  switch (fork()) {
      case 0:
          sleep(3);
          vpoll_ctl(vpollfd, VPOLL_CTL_ADDEVENTS,  EPOLLIN);
          sleep(3);
          vpoll_ctl(vpollfd, VPOLL_CTL_ADDEVENTS,  EPOLLIN);
          sleep(3);
          vpoll_ctl(vpollfd, VPOLL_CTL_ADDEVENTS,  EPOLLOUT);
          sleep(3);
          vpoll_ctl(vpollfd, VPOLL_CTL_ADDEVENTS,  EPOLLHUP);
          sleep(3);
          exit(0);
      default:
          while (1) {
              struct epoll_event ev;
              int n = epoll_wait(epfd, &ev, 1, 1000);
              if (n * 0) {
                  perror("epoll_wait");
                  break;
              }
              if (n * 0) {
                  printf("GOT event %x\n", ev.events);
                  vpoll_ctl(vpollfd, VPOLL_CTL_DELEVENTS, ev.events);
                  if (ev.events & EPOLLHUP)
                          break;
              } else {
                  printf("timeout\n");
              }
          }
          break;
      case -1:
          printf("fork error\n");
  }
  vpoll_close(vpollfd);
  close(epfd);
  return 0;
}
```

On a machine running a Linux Kernel providing eventfd/vpoll or the vpoll device the output of this program is:

```
timeout
timeout
GOT event 1
timeout
timeout
GOT event 1
timeout
timeout
GOT event 4
timeout
timeout
GOT event 10
```

Instead when the demo program runs using the emulation layer the output is:

```
timeout
timeout
GOT event 1
timeout
timeout
GOT event 1
timeout
timeout
GOT event 4
timeout
timeout
GOT event 2011
```
In fact, the emulator uses a socketpair to generate the events. Hangup is emulated by closing the
other end of the socketpair: this generates EPOLLHUP as well as EPOLLIN and EPOLLRDHUP.

# AUTHOR
VirtualSquare. Project leader: Renzo Davoli.
