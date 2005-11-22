# rfc1035 project Makefile
#
#  Copyright (C) 2005 Anthony de Boer
#
#  This program is free software; you can redistribute it and/or modify
#  it under the terms of version 2 of the GNU General Public License as
#  published by the Free Software Foundation.
#
#  This program is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#  GNU General Public License for more details.
#
#  You should have received a copy of the GNU General Public License
#  along with this program; if not, write to the Free Software
#  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA

package = rfc1035lib
version = 0.2
testdns_obj = rfc1035.o testdns.o
check_dnsauth_obj = rfc1035.o check_dnsauth.o
pv = $(package)-$(version)

all : check_dnsauth testdns

check_dnsauth : $(check_dnsauth_obj)
	cc -o $@ $(check_dnsauth_obj)

testdns : $(testdns_obj)
	cc -o $@ $(testdns_obj)

depend :
	ex -c '/^# DEPENDENCIES/,$$d' -c x Makefile
	echo '# DEPENDENCIES' >> Makefile
	cc -MM *.c >> Makefile

clean:
	rm -f *.o testdns check_dnsauth

dist:
	ln -sf . $(pv)
	sed 's/^/$(pv)\//' MANIFEST | tar cvzf $(pv).tar.gz -T -
	rm $(pv)

# DEPENDENCIES
check_dnsauth.o: check_dnsauth.c rfc1035.h
rfc1035.o: rfc1035.c rfc1035.h
testdns.o: testdns.c rfc1035.h
