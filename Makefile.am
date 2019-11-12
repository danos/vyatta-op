SUBDIRS = . tests

AM_CFLAGS = -g -I src -Wall -Wextra -Werror

opdir		 = $(datadir)/vyatta-op/templates
yangdir		 = /usr/share/configd/yang

interpdir = $(datadir)/vyatta-op/functions/interpreter
interp_DATA = functions/interpreter/vyatta-common
interp_DATA += functions/interpreter/vyatta-image-complete

bin_SCRIPTS	= scripts/vyatta-tshark.pl
bin_SCRIPTS	+= scripts/vyatta-op-cmd-wrapper
bin_SCRIPTS 	+= scripts/ping
bin_SCRIPTS 	+= scripts/show_route_forward
bin_SCRIPTS 	+= scripts/traceroute.pl
bin_SCRIPTS     += scripts/yangop-ping.pl
bin_SCRIPTS     += scripts/yangop-interface.pl
bin_SCRIPTS     += scripts/yangop-route.pl

bin_PROGRAMS = src/yangop-route/yangop-get-route
src_yangop_route_yangop_get_route_SOURCES = src/yangop-route/yangop-get-route.c
src_yangop_route_yangop_get_route_SOURCES += src/yangop-route/types.c
src_yangop_route_yangop_get_route_SOURCES += src/yangop-route/hash-table.c
src_yangop_route_yangop_get_route_SOURCES += src/yangop-route/hash-string.c
src_yangop_route_yangop_get_route_LDADD = -lmnl
src_yangop_route_yangop_get_route_LDADD += -ljansson


all-local:
cpiop = find  . ! -regex '\(.*~\|.*\.bak\|.*\.swp\|.*\#.*\#\)' -print0 | \
	cpio -0pd

install-exec-hook:
	mkdir -p $(DESTDIR)$(opdir)
	cd templates; $(cpiop) $(DESTDIR)$(opdir)
	mkdir -p $(DESTDIR)$(yangdir)
	cd yang && $(cpiop) $(DESTDIR)$(yangdir)
