/* testdns.c

  Copyright (C) 2005 Anthony de Boer

  This program is free software; you can redistribute it and/or modify
  it under the terms of version 2 of the GNU General Public License as
  published by the Free Software Foundation.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

  You should have received a copy of the GNU General Public License
  along with this program; if not, write to the Free Software
  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA

*/

#include <stdio.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>

#include "rfc1035.h"

int dnsfd;

void sloop();
void my_log_data(char *mydata, int mylen);

void barf(char *s) {
	perror(s);
	exit(1);
	}

void usage() {
	fprintf(stderr, "abusage!\n");
	exit(3);
	}

int main(int argc, char **argv) {
	char buf[512];
	struct sockaddr_in sadr;
	int rlen, rc;
	char *who = NULL;
	char *s;
	int qtype = 1;
	int authq = 0;
	int prand;
	int i;
	prand = getpid();

	while(1) {
		switch(getopt(argc, argv, "+w:At:")) {
			case 'w':
				who = strdup(optarg);
				break;
			case 'A':
				authq = 1;
				break;
			case 't':
				qtype = atoi(optarg);
				for (i=DNSQTYPEMIN;i<=DNSQTYPEMAX;i++) {
					s = dnsqtypename(i);
					if (s && !strcmp(optarg, s)) {
						qtype = i;
						break;
						}
					}
				if (!qtype) {
					fprintf(stderr, "Bad -t option\n");
					exit(3);
					}
				break;
			case EOF:
				goto doneopts;
			default:
				usage();
			}
		}
	doneopts:

	if (!who) {
		usage();
		}

	rlen = dnsencode(who, buf, prand++ & 0xffff, authq?0:1, qtype, 1);
	my_log_data (buf, rlen);

	dnsfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if (dnsfd == -1) barf("socket");

	bzero(&sadr, sizeof(sadr));
	sadr.sin_family = AF_INET;
	sadr.sin_port = htons(53);
	sadr.sin_addr.s_addr = inet_addr("192.168.240.1");
	rc = sendto(dnsfd, buf, rlen, 0, (struct sockaddr *)&sadr, sizeof(sadr));
	if (rc == -1) barf("sendto");

	sloop();
	}

void dnsrec(unsigned char *buf, int blen, int rind, int nameoff, unsigned int rtype, unsigned int rclass, unsigned int rttl, unsigned int rsize, unsigned int recoff, void *edata) {
	char *aty[] = { "Query", "Answer", "Authority", "Additional", };
	char sbuf[256];
	int rc;
	rc = dnsgetstr(buf, blen, nameoff, sbuf, sizeof(sbuf));
	printf("%s", rc < 0 ? "ERROR" : sbuf);
	rc = dnsrrstr(buf, blen, rtype, rclass, rsize, recoff, sbuf, sizeof(sbuf));
	printf(" - %s %s\n", aty[rind], rc ? "ERROR" : sbuf);
	}

/* Called when data is ready to read on socket s */
void my_read() {
	int rc;
	char buf[1024];
	rc = read(dnsfd, buf, sizeof(buf));
	if (rc == -1) barf("read");
	write(2, "\ngot\n", 5);
	my_log_data(buf, rc);
	fprintf(stderr, "parsing...\n");
	dnsparse(buf, rc, dnsrec, NULL);
	fprintf(stderr, "parsed...\n");
	close(dnsfd);
	}

void sloop() {
	int rc;
	fd_set readfds, writefds, exceptfds;
	struct timeval timeout;
	while(1) {
		FD_ZERO(&readfds);
		FD_ZERO(&writefds);
		FD_ZERO(&exceptfds);
		FD_SET(dnsfd, &readfds);
		FD_SET(dnsfd, &exceptfds);
		timeout.tv_sec = 5;
		timeout.tv_usec = 0;
		fprintf(stderr, "selecting...\n");
		rc = select(dnsfd+1, &readfds, &writefds, &exceptfds, &timeout);
		if (rc > 0) {
			fprintf(stderr, "something...\n");
			if (FD_ISSET(dnsfd, &readfds)) {
				my_read();
				}
			else if (FD_ISSET(dnsfd, &exceptfds)) {
				fprintf(stderr, "Exception on DNS socket\n");
				exit(3);
				}
			}
		else if (rc < 0 && errno != EINTR) {
			perror("select()");
			exit(3);
			}
		}
	}

#define hexdig(q) (hdigs[(q) & 0xf])

void my_log_data(char *mydata, int mylen) {
	char obuf[65];
	char *hdigs = "0123456789ABCDEF";
	char *oo1, *oo2;
	int i, v, x, z;
	while(mylen > 0) {
		oo1 = obuf;
		oo2 = obuf+48;
		z = mylen < 16 ? mylen : 16;
		for (i=0; i<16; i++) {
			if (v = (i<mylen))
				x = *(mydata++);
			*(oo1++) = v ? hexdig(x>>4) : '_';
			*(oo1++) = v ? hexdig(x) : '_';
			*(oo1++) = ' ';
			*(oo2++) = v ? (x < ' ' || x > '~') ? '.' : x : '\0';
			}
		obuf[48+z] = '\n';
		write(2, obuf, z+49);
		mylen -= 16;
		}
	}
