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
 *
 * <______> y'a pas de fichier main.c je suis perdue
 */
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdbool.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/tcp.h>

#include <pthread.h>

#define PORT 2106

extern int http_main(FILE*);

static void *f(void *arg)
{
	int   fd = (int)arg;
	FILE *fp = fdopen(fd, "w+");

	http_main(fp);
	fclose(fp);

	return NULL;
}

static bool spawn(int fd)
{
	pthread_t thread;

	if(0 != pthread_create(&thread, NULL, f, (void*)fd)) {
		perror("pthread_create");
		return false;
	}

	if(0 != pthread_detach(thread)) {
		perror("pthread_detach");
		return false;
	}

	return true;
}

static void handle(int fd)
{
	while(1) {
		struct sockaddr_in sin;
		socklen_t len = sizeof(sin);
		int client = accept(fd, (struct sockaddr*)&sin, &len);

		if(client < 0) {
			perror("accept");
			return;
		}

		if(len != sizeof(sin)) {
			perror("accept");
			return;
		}

		char addr[INET_ADDRSTRLEN];
		if(NULL == inet_ntop(sin.sin_family, &sin.sin_addr,
			addr, sizeof(addr))) {
			perror("inet_ntop");
		} else {
			short port = ntohs(sin.sin_port);
			printf("Connection from: %s:%hu\n", addr, port);
		}

		if(!spawn(client))
			return;
	}
}

static bool prepareSocket(int fd, short port)
{
	const int yes = 1;

	const struct sockaddr_in sin = {
		.sin_family = AF_INET,
		.sin_port   = htons(port),
		.sin_addr   = INADDR_ANY,
	};

	if(0 != setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes))) {
		perror("setsockopt");
		return false;
	}

	if(bind(fd, (struct sockaddr*)&sin, sizeof(sin)) < 0) {
		perror("bind");
		return false;
	}

	if(listen(fd, 0) < 0) {
		perror("bind");
		return false;
	}

	return true;
}

static int getSocket(short port)
{
	int fd = socket(AF_INET, SOCK_STREAM, SOL_TCP);
	if(fd < 0) {
		perror("socket");
		return fd;
	}

	if(!prepareSocket(fd, port)) {
		close(fd);
		return -1;
	}

	return fd;
}

int main(int argc, char *argv[static argc])
{
	const short port = argc > 1 ? atoi(argv[1]) : PORT;
	int fd = getSocket(port);

	if(fd < 0)
		return EXIT_FAILURE;

	handle(fd);

	close(fd);
	return EXIT_FAILURE;
}
