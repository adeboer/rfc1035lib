/* check_dnsauth.c

  Copyright (C) 2005,2006 Anthony de Boer

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
#include <arpa/inet.h>

#include "rfc1035.h"

#define WARNBIT 1
#define CRITBIT 2

struct nsnode {
	char *nsname;
	char *nsip;
	int queryno;
	int npos;
	int resprec;
	int critns;
	struct nsnode *next;
	};

struct rrnode {
	char *rrname;
	int bits;
	struct rrnode *next;
	};

/* glowball */
int dnsfd;
struct nsnode *nshead = NULL;
struct rrnode *rrhead = NULL;
int nbit = 1;
int expbit = 0;
char *who = NULL;
int authq = 0;
int qtype = 1;
int debug = 0;
int syncsev = WARNBIT;
int prand;

void sloop();

void barf(char *s) {
	perror(s);
	exit(3);
	}

void puke(char *s) {
	fprintf(stderr, "%s\n", s);
	exit(3);
	}

void upchuck(char *s, char *t) {
	fprintf(stderr, "%s: \"%s\"\n", s);
	exit(3);
	}

void newns(char *name, int crit) {
	struct nsnode *tns;
	char *scp, *p;
	tns = (struct nsnode *)malloc(sizeof(struct nsnode));
	if (!tns) puke("malloc failure");
	scp = strdup(name);
	p = index(scp, ':');
	if (!p) upchuck("-n arg without a colon", scp);
	*p++ = '\0';
	tns->nsname = scp;
	tns->nsip = p;
	tns->next = nshead;
	tns->queryno = prand++ & 0xffff;
	tns->npos = nbit;
	tns->critns = crit ? CRITBIT : WARNBIT;
	tns->resprec = strcmp(scp, "_expect") ? 0 : 1;
	nbit <<= 1;
	nshead = tns;
	}

struct rrnode *findrr(char *name) {
	struct rrnode *prr;
	prr = rrhead;
	while(prr) {
		if (!strcmp(name, prr->rrname)) goto foundrr;
		prr = prr->next;
		}
	prr = (struct rrnode *)malloc(sizeof(struct rrnode));
	if (!prr) puke("malloc failure");
	prr->rrname = strdup(name);
	if (!prr->rrname) puke("malloc failure");
	prr->bits = 0;
	prr->next = rrhead;
	rrhead = prr;
	foundrr:
	return prr;
	}

void newexp(char *name) {
	struct rrnode *prr = findrr(name);
	if (expbit == 0) {
		expbit = nbit;
		newns("_expect:0.0.0.0", 0);
		}
	prr->bits |= expbit;
	}

void endgame() {
	struct rrnode *prr = rrhead;
	struct nsnode *nrr = nshead;
	int allbits = nbit - 1;
	int severity = 0;
	int fudge = 0;
	char *sep = " -";
	while(prr) {
		if (debug) printf("%s has %d\n", prr->rrname, prr->bits);
		if (prr->bits != allbits) severity |= syncsev;
		prr = prr->next;
		}
	while(nrr) {
		if (nrr->resprec != 1) severity |= nrr->critns;
		nrr = nrr->next;
		}
	printf("%s %s", who, (severity & CRITBIT) ? "CRITICAL" : severity ? "WARNING" : "OK");
	nrr = nshead;
	while(nrr) {
		char *prob;
		switch (nrr->resprec) {
			case 0: prob = "NORESPONSE"; break;
			case -1: prob = "ERROR"; break;
			case -3: prob = "NXDOMAIN"; break;
			case 1: prob = NULL; break;
			default: prob = "WTF?";
			}
		if (prob) {
			printf("%s %s %s", sep, nrr->nsname, prob);
			sep = ",";
			fudge |= nrr->npos;
			}
		nrr = nrr->next;
		}
	prr = rrhead;
	while(prr) {
		printf("%s %s", sep, prr->rrname);
		sep = ",";
		if ((prr->bits | fudge) != allbits) {
			printf(" {");
			nrr = nshead;
			while(nrr) {
				if (nrr->npos & prr->bits) {
					printf(" %s", nrr->nsname);
					}
				nrr = nrr->next;
				}
			printf(" NOT");
			nrr = nshead;
			while(nrr) {
				if (nrr->resprec == 1 && !(nrr->npos & prr->bits)) {
					printf(" %s", nrr->nsname);
					}
				nrr = nrr->next;
				}
			printf("}");
			}
		prr = prr->next;
		}
	printf ("\n");
	exit ((severity & CRITBIT) ? 2 : severity ? 1 : 0);
	}

void usage() {
	fprintf(stderr, "Usage:\n"
	"  -w target\n"
	"  -A (auth query only)\n"
	"  -t TYPE\n"
	"  -n nsname:ipno (WARNING on fail)\n"
	"  -N nsname:ipno (CRITICAL on fail)\n"
	"  -e expectation\n"
	"  -C (critical on sync fail)\n"
	"  -d (debug)\n"
	);
	exit(3);
	}

int main(int argc, char **argv) {
	char *s;
	int i;
	int flags;

	prand = getpid();

	while(1) {
		switch(getopt(argc, argv, "+w:At:n:N:Ce:d")) {
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
				if (!qtype) puke("Bad -t option");
					
				break;
			case 'n':
				newns(optarg, 0);
				break;
			case 'N':
				newns(optarg, 1);
				break;
			case 'C':
				syncsev = CRITBIT;
				break;
			case 'e':
				newexp(optarg);
				break;
			case 'd':
				debug = 1;
				break;
			case EOF:
				goto doneopts;
			default:
				usage();
			}
		}
	doneopts:

	if (!who) usage();

	dnsfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if (dnsfd == -1) barf("socket");

	/* see UNPv2 p58 */
	if ((flags = fcntl(dnsfd, F_GETFL, 0)) == -1) barf("fcntl F_GETFL");
	flags |= O_NONBLOCK;
	if (fcntl(dnsfd, F_SETFL, flags) == -1) barf("fcntl F_SETFL");

	sloop();
	endgame();
	}

int sendqueries() {
	char buf[512];
	struct sockaddr_in sadr;
	int rlen, rc, qid;
	int prand = getpid();
	struct nsnode *tns = nshead;
	in_addr_t ipno;
	int sent = 0;

	while(tns) {
		if (tns->resprec == 0) {
			qid = tns->queryno;
			rlen = dnsencode(who, buf, qid, authq?0:1, qtype, 1);
			bzero(&sadr, sizeof(sadr));
			sadr.sin_family = AF_INET;
			sadr.sin_port = htons(53);
			ipno = inet_addr(tns->nsip);
			if (ipno == INADDR_NONE) {
				upchuck("Bad IP number", tns->nsip);
				}
			sadr.sin_addr.s_addr = ipno;
			rc = sendto(dnsfd, buf, rlen, 0, (struct sockaddr *)&sadr, sizeof(sadr));
			if (rc == -1) barf("sendto");
			if (debug) fprintf(stderr, "send packet %d to %s\n", qid, tns->nsip);
			sent++;
			}
		tns = tns->next;
		}
	return sent;
	}

void dnsrec(unsigned char *buf, int blen, int rind, int nameoff, unsigned int rtype, unsigned int rclass, unsigned int rttl, unsigned int rsize, unsigned int recoff, void *edata) {
	char *aty[] = { "Query", "Answer", "Authority", "Additional", };
	char sbuf[256];
	struct nsnode *nsp = (struct nsnode *)edata;
	int rc;
	rc = dnsgetstr(buf, blen, nameoff, sbuf, sizeof(sbuf));
	if (debug) printf("%s", rc < 0 ? "ERROR" : sbuf);
	rc = dnsrrstr(buf, blen, rtype, rclass, rsize, recoff, sbuf, sizeof(sbuf));
	if (debug) printf(" - %s %s\n", aty[rind], rc ? "ERROR" : sbuf);
	if (rc == 0 && rind == 1) {
		struct rrnode *prr = findrr(sbuf);
		prr->bits |= nsp->npos;
		}
	}

void my_read() {
	int blen, rc, qid;
	char buf[1024];
	struct nsnode *nsp = nshead;
	blen = read(dnsfd, buf, sizeof(buf));
	if (blen == -1) barf("read");
	qid = dnsgetid(buf);
	rc = dnsgetrcode(buf);
	if (debug) fprintf(stderr, "got response %d %d (bytes %d)\n", qid, rc, blen);
	nsp = nshead;
	while(nsp) {
		if (nsp->queryno == qid) {
			if (debug) fprintf(stderr, "parsing response...\n");
			if (rc == 0) {
				dnsparse(buf, blen, dnsrec, (void*)nsp);
				nsp->resprec = 1;
				}
			else if (rc == 3) {
				nsp->resprec = -3;
				}
			else {
				nsp->resprec = -1;
				}
			break;
			}
		nsp = nsp->next;
		}
	}

void sloop() {
	int rc;
	fd_set readfds, writefds, exceptfds;
	struct timeval timeout;
	int tmdo = 1;
	int nsecs = 5;
	while(1) {
		if (tmdo) {
			if (nsecs-- == 0) return;
			if (sendqueries() == 0) return;
			}
		FD_ZERO(&readfds);
		FD_ZERO(&writefds);
		FD_ZERO(&exceptfds);
		FD_SET(dnsfd, &readfds);
		FD_SET(dnsfd, &exceptfds);
		timeout.tv_sec = 1;
		timeout.tv_usec = 0;
		tmdo = 0;
		if (debug) fprintf(stderr, "selecting...\n");
		rc = select(dnsfd+1, &readfds, &writefds, &exceptfds, &timeout);
		if (rc > 0) {
			if (debug) fprintf(stderr, "something...\n");
			if (FD_ISSET(dnsfd, &readfds)) {
				my_read();
				}
			else if (FD_ISSET(dnsfd, &exceptfds)) {
				puke("Exception on DNS socket");
				}
			}
		else if (rc < 0 && errno != EINTR) {
			barf("select()");
			}
		else {
			tmdo = 1;
			}
		}
	}
