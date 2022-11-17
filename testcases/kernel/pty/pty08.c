// SPDX-License-Identifier: GPL-2.0-or-later
/*\
 * [Description]
 *
 * We observe a list corruption when systemd-udevd issues syscalls in the
 * virtual console sysfs nodes and in /run/udev/{data,watch} symlinks.
 * VT are just a conveninent way to generate noise that systemd-udevd picks up
 * and has been somewhat reliable at reproducing the issue.
 */

#define _GNU_SOURCE

#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <termios.h>
#include <linux/vt.h>
#include "lapi/ioctl.h"

#include "tst_test.h"
#include "tst_safe_stdio.h"
#include "tst_safe_clocks.h"
#include "tst_timer.h"

static int tty_port = 8;
static char tty_path[PATH_MAX];
static int tty_fd = -1;

static char *str_timeout_s;
static int timeout_s = -1;

static char *str_repeat;
static int repeat = 1;

static inline void __do_test(void)
{
	for (int i = tty_port; i < MAX_NR_CONSOLES; ++i) {
		ioctl(tty_fd, VT_ACTIVATE, i);
		ioctl(tty_fd, VT_DISALLOCATE, i);
	}
}

static void do_test_timeout(void)
{
	struct timespec epoch, now;

	SAFE_CLOCK_GETTIME(CLOCK_MONOTONIC_RAW, &epoch);
	do {
		__do_test();
		SAFE_CLOCK_GETTIME(CLOCK_MONOTONIC_RAW, &now);
	} while (tst_timespec_diff_ms(now, epoch) < (timeout_s * 1000));

	tst_res(TPASS, "Did not compromise dentry lists");
}

static void do_test_repeat(void)
{
	for (int i = 0; i < repeat; ++i)
		__do_test();
	tst_res(TPASS, "Did not compromise dentry lists");
}

static void do_test(void)
{
	if (timeout_s > 0)
		do_test_timeout();
	else
		do_test_repeat();
}

static void setup(void)
{
	if (tst_parse_int(str_timeout_s, &timeout_s, 1, INT_MAX))
		tst_brk(TCONF, "Invalid timeout (-t) '%s'", str_timeout_s);

        if (tst_parse_int(str_repeat, &repeat, 1, INT_MAX))
                tst_brk(TCONF, "Invalid repeat (-r) '%s'", str_repeat);

	sprintf(tty_path, "/dev/tty%d", tty_port);
	if (access(tty_path, F_OK))
		tst_brk(TCONF, "TTY(s) under test is not available in the system");

	tty_fd = SAFE_OPEN(tty_path, O_RDWR);
}

static void cleanup(void)
{
	// Reset the VT if we bailed mid-way.
	for (int i = tty_port; i < MAX_NR_CONSOLES; ++i)
		ioctl(tty_fd, VT_DISALLOCATE, i);

	close(tty_fd);
}

static struct tst_test test = {
	.options = (struct tst_option[]) {
		{ "t:", &str_timeout_s, "Timeout until test passes in seconds."},
		{ "r:", &str_repeat, "Number of repetition."},
		{}
	},
	.test_all = do_test,
	.setup = setup,
	.cleanup = cleanup,
	.needs_root = 1,
	.taint_check = TST_TAINT_W | TST_TAINT_D,
	.max_runtime = 150,
};
