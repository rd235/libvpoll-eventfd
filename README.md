## libvpoll-eventfd

**generate synthetic events for poll/select/ppoll/pselect/epoll.**

This repository includes two components:

* a patch for the Linux kernel to provide a new feature: eventfd-vpoll
* a library providing a nice interface to the new feature as well as an emulator in user space (which supports only some of the events, it is for backwards compatibility).

## the problem:

This patch implements an extension of eventfd (`EFD_VPOLL`) to define file descriptors
whose I/O events can be generated at user level. These file descriptors
trigger notifications for [p]select/[p]poll/epoll.

This feature is useful for user-level implementations of network stacks
or virtual device drivers as libraries.

Networking programs use system calls implementing the Berkeley sockets API:
`socket, accept, connect, listen, recv*, send*` etc.  Programs dealing with a
device use system calls like `open, read, write, ioctl` etc.

When somebody wants to write a library able to behave like a network stack (say
lwipv6, picotcp) or a device, they can implement functions like `my_socket,
my_accept, my_open or my_ioctl`, as drop-in replacement of their system
call counterpart.  (It is also possible to use dynamic library magic to
rename/divert the system call requests to use their 'virtual'
implementation provided by the library: `socket` maps to `my_socket`, `recv`
to `my_recv` etc).

In this way portability and compatibility is easier, using a well known API
instead of inventing new ones.

Unfortunately this approach cannot be applied to
`poll/select/ppoll/pselect/epoll`.  These system calls can refer at the same time
to file descriptors created by *real* system calls like `socket, open, signalfd`...
and to file descriptors returned by `my_open`, `your_socket`.

While it is possible to provide a partial support (e.g. using pipes or
socketpairs), a clean and complete solution is still missing (as far as I
have seen); e.g. I have not seen any clean way to generate `EPOLLPRI`,
`EPOLLERR`, etc.

Example:
Let us suppose there is an application waiting for a TCP OOB message. It uses `poll` to wait
for POLLPRI and then reads the message (e.g. by `recv`).
If I want to port that application to use a network stack implemented as a library
I have to rewrite the code about `poll` as it is not possible to receive a `POLLPRI`.
From a pipe I can just receive a `POLLIN`, I have to encode in an external data structure
any further information.
Using `EFD_VPOLL` the solution is straightforward: the function `mysocket` (used in place
of `socket` to create a file descriptor behaves as a *real* `socket`) returns a file
descriptor created by `eventfd/EFD_VPOLL`, so the `poll` system call can be left
unmodified in the code. When the OOB message is available the library can trigger
an `EPOLLPRI` and the message can be received using `my_recv`.

## The Linux kernel patch

This proposal is based on a new tag for `eventfd2(2)`: `EFD_VPOLL`.

This statement:

    fd = eventfd(EPOLLOUT, EFD_VPOLL | EFD_CLOEXEC);

creates a file descriptor for I/O event generation. In this case `EPOLLOUT` is
initially true.

Likewise all the other eventfs services, `read(2)` and `write(2)` use a 8-byte
integer argument.

`read(2)` returns the current state of the pending events.

The argument of write(2) is an or-composition of a control command
(`EFD_VPOLL_ADDEVENTS`, `EFD_VPOLL_DELEVENTS` or `EFD_VPOLL_MODEVENTS`) and the
bitmap of events to be added, deleted to the current set of pending events.
`EFD_VPOLL_MODEVENTS` completely redefines the set of pending events.

e.g.:

    uint64_t request = EFD_VPOLL_ADDEVENTS | EPOLLIN | EPOLLPRI;
		write(fd, &request, sizeof(request);

adds EPOLLIN and EPOLLPRI to the set of pending events.

There can be other approaches than `EFD_VPOLL`: e.g. add two specific new system
calls like `vpollfd_create` and `vpollfd_ctl`.
Their signature could be:

    int vpollfd_create(unsigned int init_events, int flags);

where flags are the usual `NONBLOCK/CLOEXEC`

    int vpollfd_ctl(int fd, int op, unsigned int events);

where op can be `VPOLL_ADDEVENTS`, `VPOLL_DELEVENTS`, `VPOLL_MODEVENTS`

It possible to reimplement the patch this way. It needs the definition of the new system calls.
I am proposing just a new tag for eventfd as eventfd purpose is conceptually close to the new feature.
Eventfd creates a file descriptor which generates events. The default eventfd mode uses counters while
`EFD_VPOLL` uses event flags.  The new feature can be implemented on eventfd with a very limited
impact on the kernel core code.
Instead of syscalls, the `vpollfd_create/vpollfd_ctl` API could be provided by the glibc as (very simple)
library functions, as it is the case for `eventfd_read/eventfd_write` in /usr/include/sys/eventfd.h

(It is exactly what libvpoll does, including an emulator providing a partial support of vpoll)

These are examples of messages asking for a feature like `EFD_VPOLL`:

* https://stackoverflow.com/questions/909189/simulating-file-descriptor-in-user-space
* https://stackoverflow.com/questions/1648147/running-a-simple-tcp-server-with-poll-how-do-i-trigger-events-artificially
* ... and I need it to write networking and device modules for vuos:
https://github.com/virtualsquare/vuos
(it is the new codebase of ViewOS, see www.virtualsquare.org).

### EXAMPLE of program using `EFD_VPOLL`:

The following program creates an `eventfd/EFD_VPOLL` file descriptor and then forks
a child process.  While the parent waits for events using `epoll_wait` the child
generates a sequence of events. When the parent receives an event (or a set of events)
it prints it and disarm it.
The following shell session shows a sample run of the program:

    timeout...
		timeout...
		GOT event 1
		timeout...
		GOT event 1
		timeout...
		GOT event 3
		timeout...
		GOT event 2
		timeout...
		GOT event 4
		timeout...
		GOT event 10

Program source:
```C
#include <sys/eventfd.h>
#include <sys/epoll.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>             /* Definition of uint64_t */

#ifndef EFD_VPOLL
#define EFD_VPOLL (1 << 1)
#define EFD_VPOLL_ADDEVENTS (1ULL << 32)
#define EFD_VPOLL_DELEVENTS (2ULL << 32)
#define EFD_VPOLL_MODEVENTS (3ULL << 32)
#endif

#define handle_error(msg) \
	do { perror(msg); exit(EXIT_FAILURE); } while (0)

static void vpoll_ctl(int fd, uint64_t request) {
	ssize_t s;
	s = write(fd, &request, sizeof(request));
	if (s != sizeof(uint64_t))
		handle_error("write");
}

int
main(int argc, char *argv[])
{
	int efd, epollfd;
	struct epoll_event ev;
	ev.events = EPOLLIN | EPOLLRDHUP | EPOLLERR | EPOLLOUT | EPOLLHUP | EPOLLPRI;
	ev.data.u64 = 0;

	efd = eventfd(0, EFD_VPOLL | EFD_CLOEXEC);
	if (efd == -1)
		handle_error("eventfd");
	epollfd = epoll_create1(EPOLL_CLOEXEC);
	if (efd == -1)
		handle_error("epoll_create1");
	if (epoll_ctl(epollfd, EPOLL_CTL_ADD, efd, &ev) == -1)
		handle_error("epoll_ctl");

	switch (fork()) {
		case 0:
			sleep(3);
			vpoll_ctl(efd, EFD_VPOLL_ADDEVENTS | EPOLLIN);
			sleep(2);
			vpoll_ctl(efd, EFD_VPOLL_ADDEVENTS | EPOLLIN);
			sleep(2);
			vpoll_ctl(efd, EFD_VPOLL_ADDEVENTS | EPOLLIN | EPOLLPRI);
			sleep(2);
			vpoll_ctl(efd, EFD_VPOLL_ADDEVENTS | EPOLLPRI);
			sleep(2);
			vpoll_ctl(efd, EFD_VPOLL_ADDEVENTS | EPOLLOUT);
			sleep(2);
			vpoll_ctl(efd, EFD_VPOLL_ADDEVENTS | EPOLLHUP);
			exit(EXIT_SUCCESS);
		default:
			while (1) {
				int nfds;
				nfds = epoll_wait(epollfd, &ev, 1, 1000);
				if (nfds < 0)
					handle_error("epoll_wait");
				else if (nfds == 0)
					printf("timeout...\n");
				else {
					printf("GOT event %x\n", ev.events);
					vpoll_ctl(efd, EFD_VPOLL_DELEVENTS | ev.events);
					if (ev.events & EPOLLHUP)
						break;
				}
			}
		case -1:
			handle_error("fork");
	}
	close(epollfd);
	close(efd);
	return 0;
}
```

## `/dev/vpoll`: vpoll as a virtual device (kernel module)

This is an alternative implementation of the vpoll support.

When the module vpoll.ko is loaded, udev creates the device "/dev/vpoll".

This statement:
```
fd = open("/dev/vpoll", O_RDWR | O_CLOEXEC);
```
creates a file descriptor for I/O event generation that can be used in poll/select/epoll system calls.

Events can be generated by specific `ioctl`.
```C
#define VPOLL_IOC_MAGIC '^'
#define VPOLL_IO_ADDEVENTS _IO(VPOLL_IOC_MAGIC, 1)
#define VPOLL_IO_DELEVENTS _IO(VPOLL_IOC_MAGIC, 2)
#define VPOLL_IO_SETEVENTS _IO(VPOLL_IOC_MAGIC, 3)
```

A statement like `ioctl(fd, VPOLL_IO_ADDEVENTS, EPOLLIN | EPOLLPRI)` generates a the events `EPOLLIN` and `EPOLLPRI`.
In a similar manner the ioctl tags `VPOLL_IO_DELEVENTS` and `VPOLL_IO_SETEVENTS` can be used to delete events or change the set of current events, respectively.

### Compile and load the vpoll kernel module

Pprecondition: availability of the kernel sources or at least the kernel headers of the currently running kernel.
```bash
cd linux_module
make
sudo insmod vpoll.ko
```

### EXAMPLE of program using `/dev/vpoll`:

The following program opens `/dev/vpoll` and then forks
a child process.  While the parent waits for events using `epoll_wait` the child
generates a sequence of events. When the parent receives an event (or a set of events)
it prints it and disarm it.
The following shell session shows a sample run of the program:

    timeout...
		timeout...
		GOT event 1
		timeout...
		GOT event 1
		timeout...
		GOT event 3
		timeout...
		GOT event 2
		timeout...
		GOT event 4
		timeout...
		GOT event 10

Program source:
```C
#include <sys/epoll.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <fcntl.h>

#define handle_error(msg) \
    do { perror(msg); exit(EXIT_FAILURE); } while (0)

#define VPOLL_IOC_MAGIC '^'
#define VPOLL_IO_ADDEVENTS _IO(VPOLL_IOC_MAGIC, 1)
#define VPOLL_IO_DELEVENTS _IO(VPOLL_IOC_MAGIC, 2)
#define VPOLL_IO_SETEVENTS _IO(VPOLL_IOC_MAGIC, 3)

int
main(int argc, char *argv[])
{
    int efd, epollfd;
    struct epoll_event ev;
    ev.events = EPOLLIN | EPOLLRDHUP | EPOLLERR | EPOLLOUT | EPOLLHUP | EPOLLPRI;
    ev.data.u64 = 0;

    efd = open("/dev/vpoll", O_RDWR | O_CLOEXEC);
    if (efd == -1)
        handle_error("/dev/vpoll");
    epollfd = epoll_create1(EPOLL_CLOEXEC);
        if (efd == -1)
        handle_error("epoll_create1");
    if (epoll_ctl(epollfd, EPOLL_CTL_ADD, efd, &ev) == -1)
        handle_error("epoll_ctl");

    switch (fork()) {
        case 0:
            sleep(3);
            ioctl(efd, VPOLL_IO_ADDEVENTS,EPOLLIN);
            sleep(2);
            ioctl(efd, VPOLL_IO_ADDEVENTS, EPOLLIN);
            sleep(2);
            ioctl(efd, VPOLL_IO_ADDEVENTS, EPOLLIN | EPOLLPRI);
            sleep(2);
            ioctl(efd, VPOLL_IO_ADDEVENTS, EPOLLPRI);
            sleep(2);
            ioctl(efd, VPOLL_IO_ADDEVENTS, EPOLLOUT);
            sleep(2);
            ioctl(efd, VPOLL_IO_ADDEVENTS, EPOLLHUP);
            exit(EXIT_SUCCESS);
        default:
            while (1) {
                int nfds;
                nfds = epoll_wait(epollfd, &ev, 1, 1000);
                if (nfds < 0)
                    handle_error("epoll_wait");
                else if (nfds == 0)
                    printf("timeout...\n");
                else {
                    printf("GOT event %x\n", ev.events);
                    ioctl(efd, VPOLL_IO_DELEVENTS, ev.events);
                    if (ev.events & EPOLLHUP)
                        break;
                }
            }
        case -1:
            handle_error("fork");
    }
    close(epollfd);
    close(efd);
    return 0;
}
```

## The libvpoll library

This library:

* uses `eventfd/VPOLL` if supported by the kernel
* uses the vpoll device if available
* otherwise it implements an emulator (providing only `EPOLLIN`, `EPOLLOUT` and a non standard 
version of EPOLLHUP/EPOLLRDHUP, what can be done without a specific kernel support).

The API of libvpoll is clean and simple:
```
#define VPOLL_CTL_ADDEVENTS 1
#define VPOLL_CTL_DELEVENTS 2
#define VPOLL_CTL_SETEVENTS 3

int vpoll_create(uint32_t init_events, int flags);
int vpoll_ctl(int fd, int op, uint32_t events);
int vpoll_close(int fd);
```

* `vpoll_create` returns a file descriptor for vpoll
* `vpoll_ctl` adds, deletes or changes the currently active events on fd
* `vpoll_close` closes the vpoll file descriptor.

### An example using libvpoll:
```
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/epoll.h>
#include <vpoll.h>

int main(int argc, char *argv[]) {
        int vpollfd = vpoll_create(0, FD_CLOEXEC);
        int epfd = epoll_create1(EPOLL_CLOEXEC);
        struct epoll_event reqevents={EPOLLIN | EPOLLRDHUP | EPOLLERR | EPOLLOUT | EPOLLHUP | EPOLLPRI};
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
                                if (n < 0) {
                                        perror("epoll_wait");
                                        break;
                                }
                                if (n > 0) {
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

On a machine running a Linux Kernel providing eventfd/vpoll or /dev/vpoll the output of this program is:
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
In fact, the emulator uses a socketpair to generate the events. Hangup is emulated by closing the other end of the socketpair: this generates EPOLLHUP as well as EPOLLIN and EPOLLRDHUP.

## Install

### Kernel-patch

Download from kernel.org or via git a recent version of the Linux kernel tree.

Run the following command (the current working directory must be the root of the kernel tree):
```
patch -p 1 < /path/of/this/git/clone/linux_patch/linux_patch_v5.2-rc6
```

configure, compile anda install the kernel as usual.

### libvpoll

This library requires fduserdata: https://github.com/rd235/libfduserdata

The following sequence of commands that can be used to compile install the library.
```
    mkdir build
    cd build
    cmake ..
    make
    sudo make install
```