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
#include <grp.h>
#include <pwd.h>
#include <sys/prctl.h>
#include <errno.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <signal.h>
#ifdef HAVE_SECCOMP
#include <seccomp.h>
#endif

void daemonize(void) {
	if (daemon(0, 0) == -1)
		errExit("daemon");
}

void switch_user(const char *username) {
	assert(username);

	struct passwd *pw;
	if ((pw = getpwnam(username)) == 0) {
		fprintf(stderr, "Error: can't find user nobody\n");
		exit(1);
	}

	if (setgroups(0, NULL) < 0) {
		fprintf(stderr, "Error: failed to drop supplementary groups\n");
		exit(1);
	}

	if (setgid(pw->pw_gid) < 0 || setuid(pw->pw_uid) < 0) {
		fprintf(stderr, "Error: failed  to switch  the user\n");
		exit(1);
	}
}

#ifdef HAVE_SECCOMP
static uint32_t arch_token;	// system architecture as detected by libseccomp
static const char *proc_id = NULL;

static void trap_handler(int sig, siginfo_t *siginfo, void *ucontext) {
	(void) ucontext;
	if (sig == SIGSYS) {
		fprintf(stderr, "Error: %s process killed by seccomp - syscall %d", proc_id, siginfo->si_syscall);
		char *syscall_name = seccomp_syscall_resolve_num_arch(arch_token, siginfo->si_syscall);
		if (syscall_name) {
			fprintf(stderr, " (%s)", syscall_name);
			free(syscall_name);
		}
		fprintf(stderr, "\n");
	}
}
#endif

void seccomp(const char *id, const char *str) {
#ifndef HAVE_SECCOMP
	(void) id;
	(void) str;
#else
	proc_id = id;
	char *tmp = strdup(str);
	if (!tmp)
		errExit("strdup");

	arch_token = seccomp_arch_native();
	scmp_filter_ctx ctx = seccomp_init(SCMP_ACT_TRAP);
	if (!ctx)
		goto errout;

	struct sigaction sa;
	sa.sa_sigaction = &trap_handler;
	sa.sa_flags = SA_SIGINFO;
	sigfillset(&sa.sa_mask);	// mask all other signals during the handler execution
	if (sigaction(SIGSYS, &sa, NULL) == -1)
		fprintf(stderr, "Warning: cannot handle sigaction/SIGSYS\n");

	char *syscall = strtok(tmp, ",");
	while(syscall) {
		if (seccomp_rule_add(ctx, SCMP_ACT_ALLOW, seccomp_syscall_resolve_name(syscall), 0) == -1)
			fprintf(stderr, "Warning: syscall %s not added\n", syscall);
		syscall = strtok(NULL, ",");
	}

	int rc = seccomp_load(ctx);
//seccomp_export_bpf(ctx, STDOUT_FILENO);
//seccomp_export_pfc(ctx, STDOUT_FILENO);
//	seccomp_release(ctx);
	if (rc)
		goto errout;

	free(tmp);
	return;

errout:
	fprintf(stderr, "Warning: cannot initialize seccomp\n");
	free(tmp);
#endif
}

