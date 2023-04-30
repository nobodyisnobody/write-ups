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
#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <ctype.h>

#define MAX_SIZE 0x10000

struct header {
	char *key;
	char *value;
};

struct request {
	size_t count;
	struct header *headers;

	size_t length;
	bool keepalive;
};


/* Responses {{{ */
static void resp(FILE *fp, int status, const char *title, const char *body)
{
	static const char format[] = "<!doctype html>\n"
		"<html lang=\"en\">\n"
		"	<head>\n"
		"		<meta charset=\"utf8\">\n"
		"		<title>%1$s</title>\n"
		"	</head>\n"
		"\n"
		"	<body>\n"
		"		<h1>%1$s</h1>\n"
		"		<p>%2$s</p>\n"
		"	</body>\n"
		"</html>";

	char data[0x1000];
	unsigned int size = snprintf(data, sizeof(data), format, title, body);

	fprintf(fp, "HTTP/1.1 %d %s\r\n", status, title);
	fprintf(fp, "Content-Length: %u\r\n", size);
	fputs("\r\n", fp);
	fwrite(data, 1, size, fp);

	fflush(fp);
}

// https://en.wikipedia.org/wiki/Http_error_code?useskin=vector
#define DEF_RESP(n, title, body) \
	static void resp_##n(FILE *fp) \
	{ \
		return resp(fp, n, title, body); \
	}

DEF_RESP(400, "Bad Request",                "Make sure your request is valid.");
DEF_RESP(404, "Not Found",                  "Dirbuster won't help you, noob.");
DEF_RESP(405, "Method Not Allowed",         "Please use GET or POST.");
DEF_RESP(413, "Payload Too Large",          "Body is too large.");
DEF_RESP(505, "HTTP Version Not Supported", "Please use HTTP/1.1");
/* }}} */

/* Util {{{ */
static char *str_trim(char *str)
{
	while(isspace(*str))
		str++;

	size_t len = strlen(str) - 1;
	while(isspace(str[len]))
		str[len--] = 0;

	return str;
}

static bool body_skip(FILE *fp, const struct request *req)
{
	const size_t size = req->length;
	size_t n = 0;

	while(n < size) {
		int r = fseek(fp, size - n, SEEK_CUR);

		if(r < 0)
			return false;

		n += r;
	}

	return true;
}
/* }}} */

/* GET/POST handlers {{{ */
// returns false if the connection should be closed
static bool get(FILE *fp, const struct request *req, const char *path)
{
	// Skip the body
	if(!body_skip(fp, req))
		return false;

	int fd = open(path, O_RDONLY);
	if(fd < 0) {
		resp_404(fp);
		return true;
	}

	// Header
	fputs("HTTP/1.1 200 OK\r\n", fp);
	fputs("Transfer-Encoding: chunked\r\n", fp);
	fputs("\r\n", fp);

	ssize_t size;
	char buffer[0x1000];

	// Send chunks
	while((size = read(fd, buffer, sizeof(buffer))) > 0) {
		fprintf(fp, "%lx\r\n", size);
		fwrite(buffer, 1, size, fp);
		fputs("\r\n", fp);
	}

	close(fd);

	// Final chunk
	fputs("0\r\n", fp);
	fputs("\r\n", fp);

	return true;
}

static bool post(FILE *fp, const struct request *req)
{
	const size_t size = req->length;
	size_t off = 0;

	char body[size];

	while(off < size) {
		size_t r = fread(body + off, 1, size - off, fp);

		// EOF ?
		if(0 == r)
			return false;

		off += r;
	}

	static const char response[] = "What did you expect? A web challenge?";

	fputs("HTTP/1.1 200 OK\r\n", fp);
	fprintf(fp, "Content-Length: %lu\r\n", strlen(response));
	fputs("\r\n", fp);
	fwrite(response, 1, strlen(response), fp);

	return true;
}
/* }}} */

/* Parse {{{ */
// returns false only if the connection should be closed
static bool route(FILE *fp, const struct request *req,
	const char *method, const char *path)
{
	if(0 == strcasecmp(method, "GET"))
		return get(fp, req, path + 1);
	else if(0 == strcasecmp(method, "POST"))
		return post(fp, req);

	// Valid path but invalid method
	resp_405(fp);
	return true;
}

// Handle headers, returns false to skip the request
static bool handleHeaders(FILE *fp, struct request *req)
{
	bool te   = false;
	bool size = false;

	for(size_t i = 0; i < req->count; i++) {
		const struct header *h = req->headers + i;
		const char *key = h->key;
		const char *val = h->value;

		// TODO: Connection: upgrade, keep-alive not handled properly
		if(0 == strcasecmp(key, "connection")) {
			req->keepalive = 0 == strcasecmp(val, "keep-alive");
		} else if(0 == strcasecmp(key, "content-length")) {
			req->length = atoi(val);

			if(req->length > MAX_SIZE)
				size = true;
		} else if(0 == strcasecmp(key, "transfer-encoding")) {
			te = true;
		}
	}

	// We can only have a single output
	if(te) {
		// TODO:
		return false;
	} else if(size) {
		body_skip(fp, req);
		resp_413(fp);
		return false;
	}

	return true;
}

static size_t parseHeaders(FILE *fp, struct header **out)
{
	size_t n = 0;
	struct header *headers = NULL;

	while(1) {
		char line[0x1000];

		if(NULL == fgets(line, sizeof(line), fp))
			break;

		if(0 == strcmp(line, "\n") || 0 == strcmp(line, "\r\n")) {
			*out = headers;
			return n;
		}

		char *c = strchr(line, ':');
		if(NULL == c)
			break;

		*c = 0;

		n++;
		headers = realloc(headers, n * sizeof(*headers));
		headers[n - 1] = (struct header){
			.key   = strdup(str_trim(line)),
			.value = strdup(str_trim(c + 1)),
		};
	}


	// Something went wrong
	free(headers);
	return -1;
}

/*
 * Parse the header of a request
 * If the first line is not valid, all hopes are lost, abort the connection
 *
 * returns false if the connection should be aborted
 */
static bool parse(FILE *fp, struct request *req)
{
	char line[0x1000];

	// The connection is probably already closed, no need for an answer
	if(NULL == fgets(line, sizeof(line), fp))
		return false;

	// Parse the first line
	char *saveptr = NULL;
	const char *method  = strtok_r(line, " ", &saveptr);
	const char *path    = strtok_r(NULL, " ", &saveptr);
	const char *version = strtok_r(NULL, " ", &saveptr);
	const char *end     = strtok_r(NULL, " ", &saveptr);

	// There should not be more than 3 spaces
	if(NULL != end) {
		resp_400(fp);
		return false;
	}

	// But there should be at least 3 spaces
	if(NULL == version) {
		resp_400(fp);
		return false;
	}

	// We only talk HTTP/1.1
	if(0 != strncmp(version, "HTTP/1.1", 8)) {
		resp_505(fp);
		return false;
	}

	// A valid path must start with /
	if('/' != path[0]) {
		resp_400(fp);
		return false;
	}

	// Parse headers
	ssize_t count = parseHeaders(fp, &req->headers);

	if(count < 0) {
		resp_400(fp);
		return false;
	}

	req->count = count;

	// Try to make sense of this mess
	if(!handleHeaders(fp, req)) {
		return true;
	}

	return route(fp, req, method, path);
}
/* }}} */

int http_main(FILE *fp)
{
	struct request req = {};

	do {
		if(!parse(fp, &req))
			return EXIT_FAILURE;
	} while(req.keepalive);

	return EXIT_SUCCESS;
}
