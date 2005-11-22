/* rfc1035.c

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

#include "rfc1035.h"

int dnsencode(char *name, char *buf, int id, int rd, int qtype, int qclass) {
	char *q, *p, c;
	memset(buf+3, 0, 10);
	buf[0] = (id>>8) & 0377;
	buf[1] = id & 0377;
	buf[2] = rd ? 1 : 0;
	buf[5] = 1;
	q = buf+12;
	p = buf+13;
	strcpy(p, name);
	while(c = (*p++)) {
		if (c == '.') {
			q = p - 1;
			*q = 0;
			}
		else {
			(*q)++;
			}
		}
	*p++ = (qtype >> 8) & 0377;
	*p++ = qtype & 0377;
	*p++ = (qclass >> 8) & 0377;
	*p++ = qclass & 0377;
	return p - buf;
	}

unsigned int dnsget16(unsigned char *p) {
	unsigned int rc = (p[0] & 0377) << 8;
	rc |= (p[1] & 0377);
	return rc;
	}

unsigned int dnsget32(unsigned char *p) {
	unsigned int rc = (p[0] & 0377) << 24;
	rc |= (p[1] & 0377) << 16;
	rc |= (p[2] & 0377) << 8;
	rc |= (p[3] & 0377);
	return rc;
	}

int dnsgetstr(unsigned char *buf, int blen, int noff, char *sb, int sl) {
	int nl;
	int rc = -1;
	int nr = 0;
	while (1) {
		if (noff >= blen) goto toolong;
		nl = (0377 & buf[noff++]);
		if ((nl & 0300) == 0300) {
			if (noff >= blen) goto toolong;
			noff = ((nl & 077) << 8) | (0377 & buf[noff]);
			}
		else if (nl) {
			int i;
			if (noff + nl > blen) goto toolong;
			if (nr + nl >= sl) goto toolong;
			memcpy(sb+nr, buf+noff, nl);
			nr += nl;
			noff += nl;
			sb[nr++] = '.';
			}
		else {
			break;
			}
		}
	if (nr>1) {
		nr--;
		}
	sb[nr] = '\0';
	rc = nr;
	toolong:
	return rc;
	}

void dnsparse(unsigned char *buf, int blen, dnscbf dcfun, void *edata) {
	unsigned int nrx[4];
	unsigned int rtype, rclass, rttl, rsize;
	int rind = 0;
	int j = 12;
	int nameoff;

	nrx[0] = dnsgetnqueries(buf);
	nrx[1] = dnsgetnanswers(buf);
	nrx[2] = dnsgetnauth(buf);
	nrx[3] = dnsgetnadd(buf);

	while (j < blen) {
		while (nrx[rind] == 0) {
			rind++;
			if (rind > 3) goto consideredharmful;
			}
		nrx[rind]--;
		nameoff = j;
		while (1) {
			int mbyte = buf[j++];
			if ((mbyte & 0300) == 0300) {
				j++;
				break;
				}
			else if (mbyte) {
				j += mbyte;
				if (j >= blen) goto consideredharmful;
				}
			else {
				break;
				}
			}
		if (j+4 > blen) goto consideredharmful;
		rtype = dnsget16(buf+j);
		rclass = dnsget16(buf+j+2);
		j += 4;
		if (rind > 0) {
			if (j+6 > blen) goto consideredharmful;
			rttl = dnsget32(buf+j);
			rsize = dnsget16(buf+j+4);
			j += 6;
			if (j+rsize > blen) goto consideredharmful;
			}
		else {
			rttl = rsize = 0;
			}
		dcfun(buf, blen, rind, nameoff, rtype, rclass, rttl, rsize, j, edata);
		j += rsize;
		}
	consideredharmful: {}
	}

char *qtypes[] = {
	0, "A", "NS", "MD", "MF", "CNAME", "SOA", "MB",
	"MG", "MR", "NULL", "WKS", "PTR", "HINFO", "MINFO", "MX",
	"TXT", 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, "AXFR", "MAILB", "MAILA", "ANY",
	};

char *dnsqtypename(int qtype) {
	return (qtype < 0 || qtype > (sizeof(qtypes)/sizeof(char*))) ? 0 : qtypes[qtype];
	}

int dnsrrstr(unsigned char *buf, int blen, unsigned int rtype, unsigned int rclass, unsigned int rsize, unsigned int recoff, char *sb, int sl) {
	int rc;
	char *qts = dnsqtypename(rtype);
	if (!qts || rclass != 1 || !sl) {
		rc = -1;
		}
	else if (rsize == 0) {
		rc = snprintf(sb, sl, "(no RR)");
		}
	else if (rtype == 1 && rsize == 4) {
		/* IP addr */
		rc = snprintf(sb, sl, "A %u.%u.%u.%u", buf[recoff], buf[recoff+1], buf[recoff+2], buf[recoff+3]);
		}
	else if (rtype == 2 || rtype == 5 || rtype == 12) {
		rc = snprintf(sb, sl, "%s ", qts);
		if (rc < 0 || rc >= sl) {
			goto rroops;
			}
		else {
			sb += rc;
			sl -= rc;
			}
		rc = dnsgetstr(buf, blen, recoff, sb, sl);
		}
	else if (rtype == 15 && rsize > 2) {
		unsigned int mxpref;
		mxpref = dnsget16(buf+recoff);
		rc = snprintf(sb, sl, "%s %u ", qts, mxpref);
		if (rc < 0 || rc >= sl) {
			goto rroops;
			}
		else {
			sb += rc;
			sl -= rc;
			}
		rc = dnsgetstr(buf, blen, recoff+2, sb, sl);
		}
	else {
		rc = -1;
		}
	rroops: return (rc > 0 && rc < sl) ? 0 : -1;
	}
