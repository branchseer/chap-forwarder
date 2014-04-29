/*
 * forwarder.c - pppd plugin to forward CHAP requests & responses.
 *
 * Copyright (c) 2014 patr0nus. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * 3. The name(s) of the authors of this software must not be used to
 *    endorse or promote products derived from this software without
 *    prior written permission.
 *
 * 4. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by patr0nus
 *     <patronum@outlook.com>".
 *
 * THE AUTHORS OF THIS SOFTWARE DISCLAIM ALL WARRANTIES WITH REGARD TO
 * THIS SOFTWARE, INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
 * AND FITNESS, IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR ANY
 * SPECIAL, INDIRECT OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN
 * AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING
 * OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */
#include <stddef.h>
#include <time.h>
#include "pppd.h"
#include "chap-new.h"
#include <sys/stat.h> 
#include <fcntl.h>
#include <string.h>

char pppd_version[] = VERSION;
#define CHALLENGE_FILE "/tmp/challenge"
#define RESPONSE_FILE "/tmp/response"
#define BUF_LEN 64

static void generate_challenge(int* id, unsigned char *challenge)
{
	int challenge_fd, clen;
	char buf[BUF_LEN];

	system("ifup wan &");
	challenge_fd = open(CHALLENGE_FILE, O_RDONLY);
	read(challenge_fd, buf, BUF_LEN);
	close(challenge_fd);

	*id = buf[0];
	clen = buf[1];
	memcpy(challenge, (char*)buf + 1, clen + 1);
}

static void chap_respond(int id, const unsigned char* challenge, char *name, unsigned char *secret)
{
	int challenge_fd, response_fd, clen, nlen, slen;
	char challenge_content[BUF_LEN];
	char *response_content = challenge_content;

	challenge_content[0] = id;
	clen = *challenge;
	memcpy((char*)challenge_content + 1, challenge, clen + 1);

	challenge_fd = open(CHALLENGE_FILE, O_WRONLY);
	write(challenge_fd, challenge_content, clen + 2);
	close(challenge_fd);

	response_fd = open(RESPONSE_FILE, O_RDONLY);
	read(response_fd, response_content, BUF_LEN);

	nlen = strlen(response_content);
	memcpy(name, response_content, nlen + 1);

	response_content += nlen + 1;
	slen = *response_content;
	memcpy(secret, response_content, slen + 1);
}

int chap_verify(char *name, char *ourname, int id,
			struct chap_digest_type *digest,
			unsigned char *challenge, unsigned char *response,
			char *message, int message_space)
{
	int response_fd, nlen, rlen;
	char response_content[BUF_LEN];

	nlen = strlen(name);
	memcpy(response_content, name, nlen + 1);

	rlen = *response;
	memcpy((char*)response_content + nlen + 1, response, rlen + 1);

	response_fd = open(RESPONSE_FILE, O_WRONLY);
	write(response_fd, response_content, nlen + rlen + 2);
	close(response_fd);

	return 0;
}

void plugin_init(void)
{
	info("chap-forward init");
	if (access(CHALLENGE_FILE, F_OK) == -1) mkfifo(CHALLENGE_FILE, 0777);
	if (access(RESPONSE_FILE, F_OK) == -1) mkfifo(RESPONSE_FILE, 0777);

	chap_generate_challenge_hook = generate_challenge;
	chap_respond_hook = chap_respond;
	chap_verify_hook = chap_verify;
}
