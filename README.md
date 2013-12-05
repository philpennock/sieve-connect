=============
sieve-connect
=============

This is sieve-connect.  A client for the ManageSieve protocol, as
specifed in RFC 5804.  Historically, this was MANAGESIEVE as implemented
by timsieved in Cyrus IMAP.  This software is licensed and the terms are
provided in the file "LICENSE" as supplied with this software (BSD
license without the advertising clause).

SIEVE is an RFC-specified language for mail filtering, which at time of
writing is specified in a list of RFCs at the end of this document, plus
various drafts, both IETF and individual submissions.  It's designed
to be regular enough for machines to be able to manipulate, whilst still
being editable by humans.  Alas, not many clients actually implement
this instead of embedding their own internal codes in sieve comments,
defeating the goal of being able to edit with a client of your choice.

This is not yet fully compatible with RFC 5804, but is moving towards
that from the timsieved baseline; some issues to be worked on are
documented in the "TODO" file.

sieve-connect speaks ManageSieve and supports TLS for connection privacy
and also authentication if using client certificates.  sieve-connect
will use SASL authentication; SASL integrity layers are not supported,
use TLS instead.  GSSAPI-based authentication should generally work,
provided that client and server can use a common underlaying protocol.
If it doesn't work for you, please report the issue.

sieve-connect is designed to be both a tool which can be invoked from
scripts and also a decent interactive client.  It should also be a
drop-in replacement for "sieveshell", as supplied with Cyrus IMAP.


New Versions
------------

There is an announcement-only mailing-list for new releases.  The list
is <sieve-connect-announce@spodhuis.org> and you can subscribe via one of:
 * <http://mail.globnix.net/mailman/listinfo/sieve-connect-announce>
 * <mailto:sieve-connect-announce-request@spodhuis.org?subject=subscribe>

Official announcements should be PGP-signed (by a key in the strong set).


Installing
----------

You'll need Perl5 installed and various Perl modules from CPAN, as
detailed below.  None of the mandatory modules are unusual.  A man-page is
provided.

SSL certificates are assumed to be in /etc/ssl/certs/ but this is
configured at the very start of the script.


### MacOS

For MacOS, a Homebrew Tap is provided; run:

```console
  $ sudo cpan -i Mozilla::PublicSuffix
  $ brew tap philpennock/protocols
  $ brew options sieve-connect
  $ brew install sieve-connect
```

Note that by default, GSSAPI is disabled (see Problems below) and readline can
optionally be disabled.  At time of writing, a `:recommended` `:perl`
dependency appears to be a hard requirement, not merely recommended, thus the
need to manually install `Mozilla::PublicSuffix`.


Pre-Requisites
--------------

 * `Perl5`
 * `Authen::SASL`
 * `IO::Socket::INET6`
 * `IO::Socket::SSL`         1.14 or greater
 * `Mozilla::PublicSuffix`   optional; automatic server location
 * `Net::DNS`
 * `Pod::Usage`
 * `Term::ReadKey`           optional; password prompting without echo
 * `Term::ReadLine`          optional; improves interactive mode
 * `Term::ReadLine::Gnu`     optional; adds tab-completion
 * various other Perl modules which are shipped with Perl itself


Problems
--------

If Perl segfaults upon exit, then this is very probably a Perl/Readline
interaction.  You can confirm this by using an option such as --list to
avoid entering a command-loop, and then by passing `PERL_RL=Perl` in the
environment to sieve-connect.  Eg:

```console
  $ env PERL_RL=Perl sieve-connect
```

If that avoids the failure on exit, then you appear to be affected by:
  <http://rt.cpan.org/Public/Bug/Display.html?id=37194>

Rather than rebuild Perl with `-DPERL_USE_SAFE_PUTENV`, when this affected me I
chose to avoid having readline mess with `$LINES`/`$COLUMNS` and just edited
`readline-$VER/terminal.c` to disable the call to `sh_set_lines_and_columns()`.


On some platforms, bad interactions between the `Authen::SASL::Perl` module's
GSSAPI support and the platform GSSAPI libraries have been observed to cause
Perl to segfault during authentication.  If you observe this and fixing your
libraries is not an option, take a look at the `%blacklist_auth_mechanisms`
definition in the user-editable part of the script and force-disable the
mechanism which has broken platform Perl support.


If you experience any other problems, or have better solutions to the above,
please report them.


Notes about release and packaging
---------------------------------

The first release of the X.YY tarball corresponds to version 114 in the
old svn repository, where this was just one script amongst others.

Please excuse the 'XXX' for user identifier in the ChangeLog -- I'm
keeping my email address slightly less spam-harvestable (GSSAPI
authentication to svn/DAV leaves your entire user identifier in the
logs, which includes the realm).  There's an email address in the
man-page, which might be excessively spam-filtered, and other email
addresses in the PGP key used for signing the distribution.

The PGP key used for signing is in the strong set, so if you can't
verify the key then attend a PGP keysigning party.  It's where all the,
uhm, uncool people are.  No, wait wait!  The _cool_ people.  That's it.
Yeah.  *cough*

Up to (and including) v0.85, the release version was just the number of the
svn commit, so there would be gaps in release numbers.  After that release,
the source moved to Git for revision control, and release numbers are
sequential, with gaps for major occurances (such as a v1.0, one day).


Revision Control
----------------

sieve-connect uses Git for revision control.  The public-facing canonical repo
is currently GitHub, with the authoritative repository being:

 <https://github.com/philpennock/sieve-connect>

Pull-requests, etc, are accepted there.

Note that GitHub's "Releases" feature does not provide the same tarballs as are
distributed.  The "real" tarballs are prepared with `make dist`, which
generates a tarball and a PGP detached armored signature file.

The `make tarball` step depends upon Git metadata to prepare the ChangeLog file
and get the release date and version; those are put into the file (so that
`sieve-connect --version` reports a real version) and into the manual-page.

If you clone the git repository in full, *not* work from the releases offered
by GitHub, you should be able to use `make tarball` to prepare the same tarball
I release, and audit/compare them.


RFCs
----

For this tool:

 * RFC 5804 A Protocol for Remotely Managing Sieve Scripts

For the scripts this tool moves around:

 * RFC 5228 Sieve: An Email Filtering Language
 * RFC 5229 Sieve Email Filtering: Variables Extension
   * RFC 5173 Sieve Email Filtering: Body Extension
 * RFC 5230 Sieve Email Filtering: Vacation Extension
 * RFC 5231 Sieve Email Filtering: Relational Extension
 * RFC 5232 Sieve Email Filtering: Imap4flags Extension
 * RFC 5233 Sieve Email Filtering: Subaddress Extension
 * RFC 5235 Sieve Email Filtering: Spamtest and Virustest Extensions
 * RFC 3894 Sieve Extension: Copying Without Side Effects
 * RFC 5183 Sieve Email Filtering: Environment Extension
 * RFC 5260 Sieve Email Filtering: Date and Index Extensions
 * RFC 5293 Sieve Email Filtering: Editheader Extension
 * RFC 5435 Sieve Email Filtering: Extension for Notifications
   * RFC 5436 Sieve Notification Mechanism: mailto
   * RFC 5437 Sieve Notification Mechanism: Extensible Messaging and Presence Protocol (XMPP)
 * RFC 5463 Sieve Email Filtering:  Ihave Extension
 * RFC 5429 Sieve Email Filtering: Reject and Extended Reject Extensions
 * RFC 5490 The Sieve Mail-Filtering Language -- Extensions for Checking Mailbox Status and Accessing Mailbox Metadata
 * RFC 5703 Sieve Email Filtering: MIME Part Tests, Iteration, Extraction, Replacement, and Enclosure
 * RFC 5784 Sieve Email Filtering:  Sieves and Display Directives in XML

(End of README)
