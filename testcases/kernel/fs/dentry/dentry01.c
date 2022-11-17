// SPDX-License-Identifier: GPL-2.0-or-later
/*\
 * [Description]
 *
 * Thrash a tmpfs directory structure while trying to resolve paths
 * (using the *at() libc calls).
 * The goal here is to look for a potential corruption of d_subdir in a
 * path lookup in the open/rename/unlink entry calls.
 */

#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <termios.h>
#include <unistd.h>
#include <limits.h>

#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/resource.h>

#include "tst_test.h"
#include "tst_safe_stdio.h"
#include "tst_safe_clocks.h"
#include "tst_timer.h"

static char base_dir[PATH_MAX];
static const char *files[] = {
	".f1",
	".f2",
	".f3",
	".f4",
	".f5",
	".f6",
	".f7",
	".f8",
	".f9",
	".f10",
	NULL
};
static unsigned int files_len; // Initialized in setup for convenience

struct worker {
	unsigned int id;
	pid_t pid;
	int finished:1;
};
static struct worker *workers = NULL;
static char *str_workers_len = NULL;
static int workers_len = 15;
static struct worker *current = NULL;

static char *str_timeout_s;
static int timeout_s = 120;

static char *str_priority;
static int priority = 0;

static void sa_handler_finished(int sig)
{
	(void)sig;
	current->finished = 1;
}

static int worker_run(void)
{
	struct sigaction finished_sa = {
		.sa_handler = sa_handler_finished,
		.sa_flags = 0,
	};
	int flags = O_RDWR | O_CREAT | O_CLOEXEC;
	mode_t mode = 0644;
	int dirfd = SAFE_OPEN(base_dir, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_PATH);

	sigaction(SIGUSR1, &finished_sa, NULL);

        srandom(current->pid); // Hit various and different files per worker.

        while (!current->finished) {
		unsigned int n = random() % files_len;
		const char *src = &files[n][0];
		const char *dst = &files[n][1];
		int fd;

		fd = openat(dirfd, src, flags, mode);
		if (fd < 0)
			continue;

		if (renameat(dirfd, src, dirfd, dst))
			unlinkat(dirfd, src, 0);
		else
			unlinkat(dirfd, dst, 0);
		close(fd);
	}
	close(dirfd);
	return 0;
}

static void spawn_workers(void)
{
	int i;

	memset(workers, 0, workers_len * sizeof (*workers));
	for (i = 0; i < workers_len; ++i) {
		workers[i].id = i;
		workers[i].pid = SAFE_FORK();
		if (!workers[i].pid) {
			current = &workers[i];
			current->pid = getpid();

			exit(worker_run());
		}
	}
}

static void stop_workers(void)
{
	int i;
	int wstatus;

	for (i = 0; i < workers_len; ++i) {
		tst_res(TINFO, "Stopping %d...", workers[i].pid);
		SAFE_KILL(workers[i].pid, SIGUSR1);
	}
	for (i = 0; i < workers_len; ++i) {
		tst_res(TINFO, "Waiting %d...", workers[i].pid);
		waitpid(workers[i].pid, &wstatus, 0);
	}
}

static int rm_base_dir(void)
{
	int dirfd = open(base_dir, O_RDONLY | O_DIRECTORY | O_CLOEXEC);

	if (dirfd < 0)
		return 0;
	// Remove files if any.
	for (unsigned int i = 0; i < files_len; ++i) {
		const char *src = &files[i][0]; // pre-renameat name.
		const char *dst = &files[i][1]; // post-renameat name.

		unlinkat(dirfd, src, 0);
		unlinkat(dirfd, dst, 0);
	}
	return rmdir(base_dir);
}

static void setup(void)
{
	// Process files length once and for all.
	for (files_len = 0; files[files_len]; ++files_len)
		continue;

	if (tst_parse_int(str_workers_len, &workers_len, 1, INT_MAX))
		tst_brk(TBROK, "Invalid workers count (-w) argument: '%s'",
			str_workers_len);

	if (tst_parse_int(str_timeout_s, &timeout_s, 1, INT_MAX))
		tst_brk(TBROK, "Invalid timeout (-t) '%s'", str_timeout_s);

	if (tst_parse_int(str_priority, &priority, -20, 19))
		tst_brk(TBROK, "Invalid priority (-p) '%s'", str_priority);

	// Allocate workers.
	workers = malloc(workers_len * sizeof (*workers));
	if (!workers)
		tst_brk(TCONF, "Could not allocate workers array");

	//sprintf(base_dir, "/tmp/dentry01-%04lx", random() & 0xffff);
	sprintf(base_dir, "/tmp/dentry01");
	// Reset base directory.
	if (rm_base_dir())
		tst_brk(TCONF, "Failed to remove existing base directory");
	if (mkdir(base_dir, 0755))
		tst_brk(TCONF, "Failed to create base directory");
}

static void cleanup(void)
{
	rm_base_dir();
	free(workers);
}

static void do_test(void)
{
	setpriority(PRIO_PROCESS, 0, priority);
	spawn_workers();
	sleep(timeout_s);
	stop_workers();
	tst_res(TPASS, "Did not compromise dentry lists");
}

static struct tst_test test = {
	.options = (struct tst_option[]) {
		{ "w:", &str_workers_len, "Number of forked workers" },
		{ "t:", &str_timeout_s, "Timeout until test passes in seconds." },
		{ "p:", &str_priority, "Workers priority value." },
		{}
	},
	.test_all = do_test,
	.setup = setup,
	.cleanup = cleanup,
	.needs_root = 1, // Required for setpriority >0
	.taint_check = TST_TAINT_W | TST_TAINT_D,
	.max_runtime = 5 * 60,
	.forks_child = 1,
};
