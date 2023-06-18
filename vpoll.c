/*
 *   Virtual poll/select/epoll events
 *
 *   Copyright (C) 2019  Renzo Davoli <renzo@cs.unibo.it> VirtualSquare team.
 *
 *   This library is free software; you can redistribute it and/or modify it
 *   under the terms of the GNU Lesser General Public License as published by
 *   the Free Software Foundation; either version 2.1 of the License, or (at
 *   your option) any later version.
 *
 *   You should have received a copy of the GNU Lesser General Public License
 *   along with this library; if not, write to the Free Software Foundation,
 *   Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
 */

#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdint.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <sys/ioctl.h>
#include <vpoll.h>
#include <fduserdata.h>

#define VPOLLDEV "/dev/vpoll"
#ifndef EFD_VPOLL
#define EFD_VPOLL (1 << 1)
#endif
#ifndef VPOLL_IOC_MAGIC
#define VPOLL_IOC_MAGIC '^'
#endif

static FDUSERDATA *fdtable = NULL;
static int vpolldev = 0;

/************************************ emulation mode ************************************/
static int vpollemu_create(uint32_t init_events, int flags);
static int vpollemu_close(int fd);
static int vpollemu_ctl(int fd, int op, uint32_t events);

/************************************ kernel EFD_VPOLL mode ************************************/

int vpoll_create(uint32_t init_events, int flags) {
	if (__builtin_expect(fdtable != NULL, 0))
		return vpollemu_create(init_events, flags);
	else if (vpolldev) {
		int fd = open(VPOLLDEV, O_RDWR | 
				(flags & FD_CLOEXEC ? O_CLOEXEC : 0));
		if (fd >= 0)
			ioctl(fd, _IO(VPOLL_IOC_MAGIC, VPOLL_CTL_ADDEVENTS), init_events);
		return fd;
	} else
		return eventfd(0, EFD_VPOLL |
				(flags & FD_CLOEXEC ? EFD_CLOEXEC : 0));
}

int vpoll_close(int fd) {
	if (__builtin_expect(fdtable != NULL, 0))
		return vpollemu_close(fd);
	else
	return close(fd);
}

int vpoll_ctl(int fd, int op, uint32_t events) {
	if (__builtin_expect(fdtable != NULL, 0))
		return vpollemu_ctl(fd, op, events);
	else if (vpolldev)
		return 0 - (ioctl(fd, _IO(VPOLL_IOC_MAGIC, op), events) < 0);
	else {
		uint64_t request = (((uint64_t) op) << 32) | events;
		return write(fd, &request, sizeof(request)) >= 0 ? 0 : -1;
	}
}

/************************************ emulation mode ************************************/
static inline void ignore_return(int v) {
}

static void emu_update_events(int fd, int datafd, uint32_t turnon, uint32_t turnoff) {
	char buf[4];
	//printf("%x %x\n", turnon, turnoff);
	if (turnon & EPOLLIN)
		ignore_return(write(datafd, "", 1));
	if (turnon & EPOLLOUT)
		ignore_return(read(datafd, buf, 4));
	if (turnoff & EPOLLIN)
		ignore_return(read(fd, buf, 4));
	if (turnoff & EPOLLOUT) {
		ignore_return(write(fd, "", 1));
		ignore_return(write(fd, "", 1));
	}
	if (turnon & EPOLLHUP)
		shutdown(datafd, SHUT_RDWR);
	else if (turnon & EPOLLRDHUP)
		shutdown(datafd, SHUT_WR);
}

static int vpollemu_create(uint32_t init_events, int flags) {
	int fds[2];
	int rv;
	int buflen=1;
	int *datafd;

	rv = socketpair(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK, 0, fds);
	if (rv < 0)
		return rv;
	if (flags & FD_CLOEXEC)
		fcntl(fds[0], F_SETFD, FD_CLOEXEC);
	fcntl(fds[1], F_SETFD, FD_CLOEXEC);
	setsockopt(fds[0], SOL_SOCKET, SO_SNDBUF, &buflen, sizeof(buflen));
	setsockopt(fds[1], SOL_SOCKET, SO_SNDBUF, &buflen, sizeof(buflen));
	datafd = fduserdata_new(fdtable, fds[0], int);
	if (datafd == NULL) {
		close(fds[0]);
		close(fds[1]);
		return -1;
	}
	*datafd = fds[1];
	emu_update_events(fds[0], fds[1], init_events & ~EPOLLOUT, ~init_events & EPOLLOUT);
	fduserdata_put(datafd);
	return fds[0];
}

static int vpollemu_close(int fd) {
	int *datafd = fduserdata_get(fdtable, fd);
	if (datafd == NULL)
		return -1;
	close(*datafd);
	close(fd);
	fduserdata_del(datafd);
	return 0;
}

static int vpollemu_ctl(int fd, int op, uint32_t events) {
	int *datafd = fduserdata_get(fdtable, fd);
	if (datafd == NULL)
		return -1;
	switch (op) {
		case VPOLL_CTL_ADDEVENTS: 
			emu_update_events(fd, *datafd, events, 0);
			break;
		case VPOLL_CTL_DELEVENTS: 
			emu_update_events(fd, *datafd, 0, events);
			break;
		case VPOLL_CTL_SETEVENTS: 
			emu_update_events(fd, *datafd, events, ~events);
			break;
		default: errno = EINVAL;
						 fduserdata_put(datafd);
						 return -1;
	}
	fduserdata_put(datafd);
	return 0;
}

/************************************ init/fini ************************************/
__attribute__((constructor))
	static void vpollemu_init() {
		/* use eventfd EFD_VPOLL when available */
		int testfd = eventfd(0, EFD_VPOLL | EFD_CLOEXEC);
		if (testfd >= 0)
			close(testfd);
		else {
		/* switch to device module mode */
			int testfd = open(VPOLLDEV, O_RDWR | O_CLOEXEC);
			if (testfd >= 0) {
				vpolldev = 1;
				close(testfd);
			} else
		/* switch to emulation mode if EFD_VPOLL or "/dev/vpoll" are not supported(yet). */
				fdtable = fduserdata_create(0);
		}
	}

__attribute__((destructor))
	static void vpollemu_fini() {
		if (fdtable != NULL)
			fduserdata_destroy(fdtable);
	}
