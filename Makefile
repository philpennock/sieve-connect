SCRIPTNAME=sieve-connect
SCRIPTSRC=sieve-connect.pl
PERLINT=perl5
TARPREFIX=sieve-connect
DISTFILES=$(SCRIPTSRC) ChangeLog Makefile README LICENSE

PERL5BIN=`which $(PERLINT)`
TARVERSIONMAJ=0
# Set this to .N if not dealing with first release based on a given svn version
TARVERSIONPATCH=

all: $(SCRIPTNAME) ChangeLog

# This can use non-portable commands, so shove into subdir
dist: $(DISTFILES) versionfile
	pax -w -s ",^,$(TARPREFIX)-`cat versionfile`/," $(DISTFILES) > $(TARPREFIX)-`cat versionfile`.tar
	bzip2 -9 $(TARPREFIX)-`cat versionfile`.tar

$(SCRIPTNAME): $(SCRIPTSRC)
	sed <"$(SCRIPTSRC)" >"$(SCRIPTNAME)" "1s:/.*:$(PERL5BIN):"
	chmod +x "$(SCRIPTNAME)"

ChangeLog:
	svn log | sed '/^r[0-9]/s/|[^|]*|/| XXX |/' > ChangeLog

versionfile:
	svn up
	svn info | sed -n "s/^Revision: \(.*\)/$(TARVERSIONMAJ).\1$(TARVERSIONPATCH)/p" > versionfile

clean:
	rm -f "./$(SCRIPTNAME)"

distclean: clean
	rm -f ./ChangeLog ./versionfile
