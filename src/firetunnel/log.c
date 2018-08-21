/*
 * Copyright (C) 2018 Firetunnel Authors
 *
 * This file is part of firetunnel project
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
*/
#include "firetunnel.h"
#include <syslog.h>
#include <time.h>

int logcnt = 0;
static void syslogmsg(const char *msg) {
	if (++logcnt > LOG_MSGS_MAX_TIMEOUT)
		return;

	// logging
	char *ident = (arg_server)? "firetun-s": "firetun-c";
	openlog(ident, LOG_CONS | LOG_PID | LOG_NDELAY, LOG_LOCAL1);
	syslog(LOG_INFO, "%s", msg);
	closelog();
}

void logmsg(char *fmt, ...) {
	va_list args;
	va_start(args,fmt);
	char *msg;
	if (vasprintf(&msg, fmt, args) == -1)
		errExit("vasprintf");
	va_end(args);

	// write to syslog
	syslogmsg(msg);

	// write to console
	time_t t = time(NULL);
	struct tm* tm_info = localtime(&t);
	char timestamp[26];
	strftime(timestamp, 26, "%Y-%m-%d %H:%M:%S", tm_info);
	fprintf(stderr, "%s %s", timestamp, msg);
	free(msg);

}
