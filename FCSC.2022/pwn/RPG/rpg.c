/* SPDX-License-Identifier: GPL-2.0-or-later
 *
 * This program is free software: you can redistribute it and/or modify it under
 * the terms of the GNU General Public License as published by the Free Software
 * Foundation, either version 2 of the License, or (at your option) any later
 * version.
 * 
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
 * FOR A PARTICULAR PURPOSE. See the GNU General Public License for more
 * details.
 * 
 * You should have received a copy of the GNU General Public License along with
 * this program. If not, see <https://www.gnu.org/licenses/>.
 */

#define _POSIX_C_SOURCE 200809
#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <time.h>

int message(const char *fmt, ...)
{
	FILE *fp = stdout;
	char ts[sizeof("[YYYY-MM-DD HH:MM:SS] ")];

	time_t t = time(NULL);
	const struct tm *tm = localtime(&t);

	/* Write the date */
	strftime(ts, sizeof(ts), "[%F %H:%M:%S] ", tm);
	fwrite(ts, sizeof(ts), 1, fp);

	/* Write the message */
	va_list ap;
	va_start(ap, fmt);
	int ret = vfprintf(fp, fmt, ap);
	va_end(ap);

	fputc('\n', fp);

	return ret;
}

int main(void)
{
	char *name  = NULL;
	size_t size = 0;

	/* Disable buffering on stdio */
	setbuf(stdin,  NULL);
	setbuf(stdout, NULL);

	/* Ask for a name */
	printf("name> ");
	if(0 > getline(&name, &size, stdin)) {
		perror("getline");
		return EXIT_FAILURE;
	}
	name[strcspn(name, "\n")] = 0;

	/* Open the RNG source */
	FILE *fp = fopen("/dev/urandom", "r");

	if(NULL == fp) {
		perror("fopen");
		return EXIT_FAILURE;
	}

	message("%s logged in", name);

	/* Read messages */
	while(1) {
		char *msg   = NULL;
		size_t size = 0;

		if(0 > getline(&msg, &size, stdin)) {
			perror("getline");
			return EXIT_FAILURE;
		}
		msg[strcspn(msg, "\n")] = 0;

		/* Handle commands */
		if('/' == msg[0] && '/' != msg[1]) {
			const char *cmd = strtok(msg + 1, " ");
			const char *arg = strtok(NULL, "");

			if(0 == strcmp(cmd, "quit")) {
				if(arg)
					message("%s quit (%s)", name, arg);
				else
					message("%s quit", name);
				break;
			} else if(0 == strcmp(cmd, "me")) {
				message("*** %s %s ***", name, arg);
			} else if(0 == strcmp(cmd, "nick")) {
				message("%s is now known as %s", name, arg);

				if(strlen(arg) >= size)
					name = realloc(name, size + 1);

				strcpy(name, arg);
			} else if(0 == strcmp(cmd, "roll")) {
				/* You can play with *very large* dices */
				size_t mod = atol(arg);
				size_t r = 0;

				if(0 == mod) {
					message("Cannot roll 0-faced dices");
					continue;
				}

				if(sizeof(r) != fread(&r, 1, sizeof(r), fp)) {
					perror("fread");
					continue;
				}

				r %= mod;

				message("%s rolled 1d%lu: %lu", name, mod, r);
			} else {
				message("invalid command: %s", cmd);
			}
		} else {
			/* regular message */
			const char *m = msg;
			if('/' == m[0])
				m++;

			message("%s: %s", name, m);
		}

		free(msg);
	}
}
