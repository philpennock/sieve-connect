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
PERL5BIN=`sh ./find-perl58.sh`
SED=sed
CHMOD=chmod
RM=rm

# These you probably don't want to adjust
SCRIPTNAME=sieve-connect
MANPAGE=sieve-connect.1
SCRIPTSRC=sieve-connect.pl
TARPREFIX=sieve-connect
DISTFILES=$(SCRIPTSRC) $(MANPAGE) ChangeLog Makefile README LICENSE TODO find-perl58.sh
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

# making the man-page is dependent upon files not distributed, so they're
# regenerated, so we don't list it as a dependency here -- instead we
# assume that the maintainer created it for us (as a tarball depenency)
install-man:
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
ChangeLog: .svn/text-base/*
	TZ='' svn log | sed '/^r[0-9]/s/|[^|]*|/| XXX |/' > ChangeLog

# NB: Id tag is already in zulu time, so no problem with program itself
datefile versionfile: .svn/text-base/*
	@grep -q "Copyright.*\\<`date +%Y`" $(SCRIPTSRC) || { echo "Current year not in $(SCRIPTSRC) Copyright line"; false; }
	@grep -q "Copyright.*\\<`date +%Y`" LICENSE || { echo "Current year not in LICENSE Copyright line"; false; }
	TZ='' svn up
	TZ='' svn info | sed -n "s/^Revision: \(.*\)/$(TARVERSIONMAJ).\1$(TARVERSIONPATCH)/p" > versionfile
	TZ='' svn info | sed -n 's/^Last Changed Date: \([^ ]*\) .*/\1/p' >datefile

distclean: clean
	$(RM) -f "./$(MANPAGE)" ./ChangeLog ./versionfile ./datefile
