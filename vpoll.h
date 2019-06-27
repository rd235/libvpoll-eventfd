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
 *
 *   Example of usage:
 *      // generate a file descriptor (you'll use this in poll/select/epoll...)
 *      vpollfd = vpoll_create(EPOLLOUT, FD_CLOEXEC);
 *      // when vpollfd need to signal POLLIN to all the interested poll/select/epoll (if any)
 *      vpoll_ctl(vpollfd, VPOLL_CTL_ADDEVENTS, EPOLLIN);
 *      // clear the EPOLLIN event in this way:
 *      vpoll_ctl(vpollfd, VPOLL_CTL_DELEVENTS, EPOLLIN);
 *      // VPOLL_CTL_SETEVENTS sets all the pending event map
 *      // close vpollfd when it is no longer needed:
 *      vpoll_close(vpollfd);
 *     
 *   This library uses the EFD_VPOLL flag of eventfd(2) where available, otherwise it implements
 *   a user-space emulation based on socketpair(2).
 *   While eventfd provide full support to all the EPOLL events (including those not defined yet),
 *   the emulation code supports EPOLLIN, EPOLLOUT, EPOLLHUP only.
 *   (in emulation mode it is not possible to file further events after an EPOLLHUP).
 */

#ifndef VPOLLEMU_H
#define VPOLLEMU_H
#include <stdint.h>

#define VPOLL_CTL_ADDEVENTS 1
#define VPOLL_CTL_DELEVENTS 2
#define VPOLL_CTL_SETEVENTS 3

int vpoll_create(uint32_t init_events, int flags);
int vpoll_ctl(int fd, int op, uint32_t events);
int vpoll_close(int fd);

#endif
