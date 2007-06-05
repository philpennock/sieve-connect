SCRIPTNAME=sieve-connect
MANPAGE=sieve-connect.1
SCRIPTSRC=sieve-connect.pl
PERLINT=perl5
TARPREFIX=sieve-connect
DISTFILES=$(SCRIPTSRC) $(MANPAGE) ChangeLog Makefile README LICENSE
PGPSIGNKEY=0x3903637F

PERL5BIN=`which $(PERLINT)`
TARVERSIONMAJ=0
# Set this to .N if not dealing with first release based on a given svn version
TARVERSIONPATCH=

all: $(SCRIPTNAME) ChangeLog

dist: tarball pgpsig

# This can use non-portable commands, so shove into subdir
tarball: $(DISTFILES) versionfile
	pax -w -s ",^,$(TARPREFIX)-`cat versionfile`/," $(DISTFILES) > $(TARPREFIX)-`cat versionfile`.tar
	bzip2 -9 $(TARPREFIX)-`cat versionfile`.tar

pgpsig: tarball versionfile
	gpg -a --detach-sign --default-key $(PGPSIGNKEY) $(TARPREFIX)-`cat versionfile`.tar.bz2

bin $(SCRIPTNAME): $(SCRIPTSRC)
	sed <"$(SCRIPTSRC)" >"$(SCRIPTNAME)" "1s:/.*:$(PERL5BIN):"
	chmod +x "$(SCRIPTNAME)"

man $(MANPAGE): $(SCRIPTSRC) datefile versionfile
	pod2man -n "$(SCRIPTNAME)" -c '' -d "`cat datefile`" -r "`cat versionfile`" "$(SCRIPTSRC)" >"$(MANPAGE)"

ChangeLog:
	svn log | sed '/^r[0-9]/s/|[^|]*|/| XXX |/' > ChangeLog

datefile versionfile:
	svn up
	svn info | sed -n "s/^Revision: \(.*\)/$(TARVERSIONMAJ).\1$(TARVERSIONPATCH)/p" > versionfile
	svn info | sed -n 's/^Last Changed Date: \([^ ]*\) .*/\1/p' >datefile

clean:
	rm -f "./$(SCRIPTNAME)"

distclean: clean
	rm -f "./$(MANPAGE)" ./ChangeLog ./versionfile ./datefile
