# These targets are those you might want to override at install time
INSTALLPROG=install
INSTALLROOT=
INSTALLARGS=
PREFIX=/usr/local
BINDIR=bin
BINPERM=0755
# Might use: MANDIR=share/man
MANDIR=man
MANSECTDIR=man1
MANPERM=0644
PERL5BIN=`which $(PERLINT)`
SED=sed
CHMOD=chmod
RM=rm

# These you probably don't want to adjust
SCRIPTNAME=sieve-connect
MANPAGE=sieve-connect.1
SCRIPTSRC=sieve-connect.pl
PERLINT=perl5
TARPREFIX=sieve-connect
DISTFILES=$(SCRIPTSRC) $(MANPAGE) ChangeLog Makefile README LICENSE
GPG=gpg
PGPSIGNKEY=0x3903637F

TARVERSIONMAJ=0
# Set this to .N if not dealing with first release based on a given svn version
TARVERSIONPATCH=

# ======================================================================
# Targets for builders/installers

all: $(SCRIPTNAME)

install: all install-bin install-man

install-bin: $(SCRIPTNAME)
	$(INSTALLPROG) -m $(BINPERM) $(INSTALLARGS) $(SCRIPTNAME) $(INSTALLROOT)$(PREFIX)/$(BINDIR)

install-man: $(MANPAGE)
	$(INSTALLPROG) -m $(MANPERM) $(INSTALLARGS) $(MANPAGE) $(INSTALLROOT)$(PREFIX)/$(MANDIR)/$(MANSECTDIR)

bin $(SCRIPTNAME): $(SCRIPTSRC)
	$(SED) <"$(SCRIPTSRC)" >"$(SCRIPTNAME)" "1s:/.*:$(PERL5BIN):"
	$(CHMOD) +x "$(SCRIPTNAME)"

clean:
	$(RM) -f "./$(SCRIPTNAME)"

# ======================================================================
# Targets after here are for distributors

dist: tarball pgpsig

# This can use non-portable commands, so shove into subdir
tarball: $(DISTFILES) versionfile
	pax -w -s ",^,$(TARPREFIX)-`cat versionfile`/," $(DISTFILES) > $(TARPREFIX)-`cat versionfile`.tar
	bzip2 -9 $(TARPREFIX)-`cat versionfile`.tar

pgpsig: tarball versionfile
	$(GPG) -a --detach-sign --default-key $(PGPSIGNKEY) $(TARPREFIX)-`cat versionfile`.tar.bz2

man $(MANPAGE): $(SCRIPTSRC) datefile versionfile
	pod2man -n "$(SCRIPTNAME)" -c '' -d "`cat datefile`" -r "`cat versionfile`" "$(SCRIPTSRC)" >"$(MANPAGE)"

# filter is against spammers (see README)
ChangeLog:
	svn log | sed '/^r[0-9]/s/|[^|]*|/| XXX |/' > ChangeLog

datefile versionfile:
	svn up
	svn info | sed -n "s/^Revision: \(.*\)/$(TARVERSIONMAJ).\1$(TARVERSIONPATCH)/p" > versionfile
	svn info | sed -n 's/^Last Changed Date: \([^ ]*\) .*/\1/p' >datefile

distclean: clean
	$(RM) -f "./$(MANPAGE)" ./ChangeLog ./versionfile ./datefile
