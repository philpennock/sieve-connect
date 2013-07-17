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
SCRIPTSRC=sieve-connect.pre.pl
SCRIPTDIST=sieve-connect.pl
TARPREFIX=sieve-connect
DISTFILES=$(SCRIPTDIST) $(MANPAGE) ChangeLog Makefile README.md LICENSE TODO find-perl58.sh
GPG=gpg
PGPSIGNKEY=0x3903637F

# ======================================================================
# Targets for builders/installers

all: $(SCRIPTNAME)

install: all install-bin install-man

install-bin: $(SCRIPTNAME)
	$(INSTALLPROG) -m $(BINPERM) $(INSTALLARGS) $(SCRIPTNAME) $(INSTALLROOT)$(PREFIX)/$(BINDIR)/./

# making the man-page is dependent upon files not distributed, so they're
# regenerated, so we don't list it as a dependency here -- instead we
# assume that the maintainer created it for us (as a tarball depenency)
install-man:
	$(INSTALLPROG) -m $(MANPERM) $(INSTALLARGS) $(MANPAGE) $(INSTALLROOT)$(PREFIX)/$(MANDIR)/$(MANSECTDIR)/./

bin $(SCRIPTNAME): $(SCRIPTDIST)
	$(SED) <"$(SCRIPTDIST)" >"$(SCRIPTNAME)" "1s:/.*:$(PERL5BIN):"
	$(CHMOD) +x "$(SCRIPTNAME)"

clean:
	$(RM) -f "./$(SCRIPTNAME)"

# ======================================================================
# Targets after here are for distributors

dist: tarball pgpsig

# The presence of SCRIPTSRV and git rules breaks install from outside the git
# repository; we fix it by just ripping out the distributors section from the
# tarball Makefile.  So "makefile" in git and for use when making a release.
# "Makefile" for distribution.  BSD make prefers "makefile" to "Makefile", so
# we can still use distributor targets when both are present.
Makefile: makefile
	sed '/Targets after here are for distributors/,$$d' < makefile > Makefile

$(SCRIPTDIST): $(SCRIPTSRC) versionfile
	perl -MFile::Slurp -p < $(SCRIPTSRC) > $(SCRIPTDIST) -e ' \
		BEGIN { $$newver = read_file("versionfile"); chomp $$newver; }; \
		next unless /VERSION.*MAGIC LINE REPLACED IN DISTRIBUTION/; \
		$$_ = qq{our \$$VERSION = '"'"'$$newver'"'"';\n}; \
	'
	chmod +x $(SCRIPTDIST)

# This can use non-portable commands, so shove into subdir
tarball: $(DISTFILES) versionfile
	pax -w -s ",^,$(TARPREFIX)-`cat versionfile`/," $(DISTFILES) > $(TARPREFIX)-`cat versionfile`.tar
	bzip2 -9 $(TARPREFIX)-`cat versionfile`.tar

pgpsig: tarball versionfile
	$(GPG) -a --detach-sign --default-key $(PGPSIGNKEY) $(TARPREFIX)-`cat versionfile`.tar.bz2

man $(MANPAGE): $(SCRIPTDIST) datefile versionfile
	pod2man -n "$(SCRIPTNAME)" -c '' -d "`cat datefile`" -r "`cat versionfile`" "$(SCRIPTDIST)" >"$(MANPAGE)"

# filter is against spammers (see README)
ChangeLog: .git/HEAD
	TZ='' git log --decorate=short --date=iso -- sieve-connect.\* | sed '/^Author:/s/ <.*//' > ChangeLog

datefile versionfile: .git/HEAD
	@grep -q "Copyright.*\\<`date +%Y`" $(SCRIPTSRC) || { echo "Current year not in $(SCRIPTSRC) Copyright line"; false; }
	@grep -q "Copyright.*\\<`date +%Y`" LICENSE || { echo "Current year not in LICENSE Copyright line"; false; }
	TZ='' git describe --match 'v[0-9]*' --dirty=-XX | sed -n 's/^v//p' > versionfile
	TZ='' git show -s --format=%ci HEAD | cut -d ' ' -f 1 > datefile

distclean: clean
	$(RM) -f "./$(MANPAGE)" ./ChangeLog ./versionfile ./datefile ./$(SCRIPTDIST) ./Makefile
