/* rfc1035.h

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

/* --- encoding routine --- */

/* dnsencode: encode a DNS query.  Passed:
 name - string name to query (eg. "www.example.com")
 buf - a buffer in which to store the query; must be at least 17 octets
 longer than the name.
 id - query ID, 16-bit quantity
 rd - nonzero for recursion-desired, zero for no recursion
 qtype - query type (1==A)
 qclass - query class (1=IN)
Returns number of octets encoded in buf.
*/
int dnsencode(char *name, char *buf, int id, int rd, int qtype, int qclass);

/* --- decoding routines --- */

/* for internal use only */
unsigned int dnsget16(unsigned char *p);

/* return query ID from response buffer x */
#define dnsgetid(x) dnsget16(x)

/* return flags word from response buffer x */
#define dnsgetflags(x) dnsget16((x)+2)

/* return the number of contained queries from response buffer x */
#define dnsgetnqueries(x) dnsget16((x)+4)

/* return the number of contained answers from response buffer x */
#define dnsgetnanswers(x) dnsget16((x)+6)

/* return the number of contained authority records from response buffer x */
#define dnsgetnauth(x) dnsget16((x)+8)

/* return the number of contained additional records from response buffer x */
#define dnsgetnadd(x) dnsget16((x)+10)

/* return the authority flag from response buffer x */
#define dnsgetaa(x) ((dnsgetflags(x) >> 10) & 1)

/* return the response code from response buffer x (0=OK, 3=NXDOMAIN,
other nonzero values indicate other problems per 1035 page 27 */
#define dnsgetrcode(x) (dnsgetflags(x) & 15)

/* Callback that gets asked about each parsed record; you have to write one.
 buf - the original buffer
 blen - size thereof
 rind - type of record (0=question, 1=answer, 2=authority, 3=additional)
 nameoff - offset in buf at which name starts
 rtype - record type (1=A etc)
 rclass - record class (1=IN)
 rttl - TTL
 rsize - size of resource data
 recoff - offset in buf at which resource data starts
 edata - extra data (cast a pointer to your own struct, whatever)
*/
typedef void (*dnscbf)(unsigned char *buf, int blen, int rind, int nameoff, unsigned int rtype, unsigned int rclass, unsigned int rttl, unsigned int rsize, unsigned int recoff, void *edata);

/* parser:
 buf - buffer containing DNS packet
 blen - length of packet
 dcfun - callback function that will be called for each record (see above)
 edata - extra data pointer to pass to callback (so you can tell it which
 record it's in at the time)
*/
void dnsparse(unsigned char *buf, int blen, dnscbf dcfun, void *edata);

/* get a labelled string out of a DNS record.  This is useful in your
callback routine to either get the name (using nameoff, in all cases) or
using recoff if the payload is a name.
 buf - the original buffer
 blen - size thereof
 noff - name offset in record
 sb - string buffer
 sl - size of buffer
 RETURN: length of string, or -1 on error
*/
int dnsgetstr(unsigned char *buf, int blen, int noff, char *sb, int sl);

#define DNSQTYPEMIN 1
#define DNSQTYPEMAX 255

/* return the name of a query type.  NULL is returned for invalid ones.
 1 is "A" and so on.  The useful range is DNSQTYPEMIN through DNSQTYPEMAX.
*/
char *dnsqtypename(int qtype);

/* generate a string describing an RR.  Pass:
 buf - the original buffer
 blen - size thereof
 rtype - record type (1=A etc)
 rclass - record class (1=IN)
 rsize - size of resource data
 recoff - offset in buf at which resource data starts
 sb - string buffer
 sl - size of buffer
Returns 0 on success.
*/
int dnsrrstr(unsigned char *buf, int blen, unsigned int rtype, unsigned int rclass, unsigned int rsize, unsigned int recoff, char *sb, int sl);
