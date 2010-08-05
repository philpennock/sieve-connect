#!/usr/bin/perl
#
# $HeadURL$
#
# timsieved client script
#
# Copyright © 2006-2010 Phil Pennock.  All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
# 1. Redistributions of source code must retain the above copyright
#    notice, this list of conditions and the following disclaimer.
# 2. Redistributions in binary form must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer in the
#    documentation and/or other materials provided with the distribution.
# 3. The name of the author may not be used to endorse or promote products
#    derived from this software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
# IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
# OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
# IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT,
# INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
# (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
# SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
# CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
# LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
# OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
# SUCH DAMAGE.
#

use warnings;
use strict;

# If you can't update /etc/services to contain an entry for 'sieve' and you're
# not using 4190 (specified in RFC 5804) then you might want to change the
# default port-number in the parentheses here:
my $DEFAULT_PORT = 'sieve(4190)';

# These are the defaults, some may be overriden on the command-line.
my %ssl_options = (
	SSL_version	=> 'TLSv1',
	SSL_cipher_list	=> 'ALL:!aNULL:!NULL:!LOW:!EXP:!ADH:@STRENGTH',
	SSL_verify_mode	=> 0x01,
	SSL_ca_path	=> '/etc/ssl/certs',
);
# These defaults can be overriden on the cmdline:
my ($forbid_clearauth, $forbid_clearchan) = (0, 0);

my @cmd_localfs_ls = qw( ls -C );

# ######################################################################
# No user-serviceable parts below

our $VERSION = 0;
my $svn_revision = '$Revision$';
if ($svn_revision =~ /^.Revision:\s*(\d+)\s*\$\z/) {
	$svn_revision = $1;
	$VERSION = '0.' . $1;
} else {
	$svn_revision = '0 because unknown';
}

use Authen::SASL 2.11 qw(Perl);
# 2.11: first version with non-broken DIGEST-MD5
#       Earlier versions don't allow server verification
#       NB: code still explicitly checks for a new-enough version, so
#           if you have an older version of Authen::SASL and know what you're
#           doing then you can remove this version check here.  I advise
#           against it, though.
# Perl: Need a way to ask which mechanism to send
use Authen::SASL::Perl::EXTERNAL; # We munge inside its private stuff.
use Cwd qw();
use Errno;
use File::Basename qw();
use File::Spec;
use Getopt::Long;
use IO::File;
use IO::Socket::INET6;
use IO::Socket::SSL 0.97; # SSL_ca_path bogus before 0.97
use MIME::Base64;
use Net::DNS;
use Pod::Usage;
use POSIX qw/ strftime /;
use Term::ReadKey;
# interactive mode will attempt to pull in Term::ReadLine too.

my $DEBUGGING = 0;

sub do_version_display {
	print "${0}: Version $VERSION\n";
	if ($DEBUGGING) {
		my @do_require = (
			'Authen::SASL::Perl::GSSAPI',
			'Term::ReadLine',
		);
		foreach my $r (@do_require) {
			(my $rr = $r) =~ s,::,/,g;
			eval { require "$rr.pm" };
		}
		foreach my $mod (
				'Authen::SASL',
				'Authen::SASL::Perl',
				'IO::Socket::INET6',
				'IO::Socket::SSL',
				'Term::ReadKey',
				@do_require) {
			my $vname = "${mod}::VERSION";
			my $ver;
			eval { no strict 'refs'; $ver = ${$vname} };
			if (defined $ver) {
				print "  Module $mod Version $ver\n";
			} else {
				print "  Module $mod -- no version number available\n";
			}
		}
	}
	exit 0;
}

sub debug;
sub sent;
sub ssend;
sub sget;
sub sfinish;
sub received;
sub closedie;
sub closedie_NOmsg;
sub die_NOmsg;

my $DEBUGGING_SASL = 0;
my $DATASTART = tell DATA;
my $localsievename;
my $remotesievename;
my $port = undef;
my ($user, $authzid, $authmech, $sslkeyfile, $sslcertfile, $passwordfd);
my $prioritise_auth_external = 0;
my $dump_tls_information = 0;
my $opt_version_req = 0;
my $ignore_server_version = 0;
my $no_srv = 0;
my ($server, $realm);
my $net_domain = AF_UNSPEC;
my $action = 'command-loop';
my $execscript;
GetOptions(
	"localsieve=s"	=> \$localsievename,
	"remotesieve=s"	=> \$remotesievename,
	"server|s=s"	=> \$server,
	"port|p=s"	=> \$port, # not num, allow service names
	"nosrv"		=> \$no_srv,
	"user|u=s"	=> \$user,
	"realm|r=s"	=> \$realm,
	"authzid|authname|a=s"	=> \$authzid, # authname for sieveshell compat
	"authmech|m=s"	=> \$authmech,
	"passwordfd=n"	=> \$passwordfd,
	"clientkey=s"	=> \$sslkeyfile,
	"clientcert=s"	=> \$sslcertfile,
	"clientkeycert=s" => sub { $sslkeyfile = $sslcertfile = $_[1] },
	"notlsverify|nosslverify" => sub { $ssl_options{'SSL_verify_mode'} = 0x00 },
	"noclearauth"	=> \$forbid_clearauth,
	"noclearchan"	=> sub { $forbid_clearauth = $forbid_clearchan = 1 },
	"4"		=> sub { $net_domain = AF_INET },
	"6"		=> sub { $net_domain = AF_INET6 },
	"debug"		=> \$DEBUGGING,
	"debugsasl"	=> \$DEBUGGING_SASL,
	"dumptlsinfo|dumpsslinfo"	=> \$dump_tls_information,
	"ignoreserverversion"	=> \$ignore_server_version,
	# option names can be short-circuited, $action is complete:
	"upload"	=> sub { $action = 'upload' },
	"download"	=> sub { $action = 'download' },
	"list"		=> sub { $action = 'list' },
	"delete"	=> sub { $action = 'delete' },
	"activate"	=> sub { $action = 'activate' },
	"deactivate"	=> sub { $action = 'deactivate' },
	"checkscript"   => sub { $action = 'checkscript' },
	"exec|e=s"	=> sub { $execscript = $_[1]; $action='command-loop' },
	'help|?'	=> sub { pod2usage(0) },
	'man'		=> sub { pod2usage(-exitstatus => 0, -verbose => 2) },
	'version'	=> \$opt_version_req, # --version --debug should work
) or pod2usage(2);
# We don't implement HAVESPACE <script> <size>

do_version_display() if $opt_version_req;

if (defined $ARGV[0] and not defined $server) {
	# sieveshell compatibility.
	my $where = $ARGV[0];
	if ($where =~ m!^\[([^]]+)\]:(.+)\z!) {
		$server = $1; $port = $2;
	} elsif ($where =~ m!^\[([^]]+)\]\z!) {
		$server = $1;
	} elsif ($where =~ m!^(.+):([^:]+)\z!) {
		$server = $1; $port = $2;
	} else {
		$server = $where;
	}
}
unless (defined $server) {
	$server = 'localhost';
	if (exists $ENV{'IMAP_SERVER'}
			and $ENV{'IMAP_SERVER'} !~ m!^/!) {
		$server = $ENV{'IMAP_SERVER'};
		# deal with a port number.
		unless ($server =~ /:.*:/) { # IPv6 address literal
			$server =~ s/:\d+\z//;
		}
	}
}

die "Bad server name\n"
	unless $server =~ /^[A-Za-z0-9_.:-]+\z/;
if (defined $port) {
	die "Bad port specification\n"
		unless $port =~ /^[A-Za-z0-9_()-]+\z/;
}

unless (defined $user) {
	if ($^O eq "MSWin32") {
		# perlvar documents always "MSWin32" on Windows ...
		# what about 64bit windows?
		if (exists $ENV{USERNAME} and length $ENV{USERNAME}) {
			$user = $ENV{USERNAME};
		} elsif (exists $ENV{LOGNAME} and length $ENV{LOGNAME}) {
			$user = $ENV{LOGNAME};
		} else {
			die "Unable to figure out a default user, sorry.\n";
		}
	} else {
		$user = getpwuid $>;
	}
	# this should handle the non-mswin32 case if 64bit _is_ different.
	die "Unable to figure out a default user, sorry!\n"
		unless defined $user;
}

if ((defined $sslkeyfile and not defined $sslcertfile) or
    (defined $sslcertfile and not defined $sslkeyfile)) {
	die "Need both a client key and cert for SSL certificate auth.\n";
}
if (defined $sslkeyfile) {
	$ssl_options{SSL_use_cert} = 1;
	$ssl_options{SSL_key_file} = $sslkeyfile;
	$ssl_options{SSL_cert_file} = $sslcertfile;
	$prioritise_auth_external = 1;
}

if (defined $localsievename and not defined $remotesievename) {
	$remotesievename = $localsievename;
}

if (defined $localsievename and $action =~ /upload|checkscript/) {
	-r $localsievename or die "unable to read \"$localsievename\": $!\n";
}
if ($action eq 'download' and not defined $localsievename) {
	die "Need a local filename (or '-') for download.\n";
}
if (($action eq 'activate' or $action eq 'delete' or $action eq 'download')
		and not defined $remotesievename) {
	die "Need a remote scriptname for '$action'\n";
}
if ($action eq 'deactivate' and defined $remotesievename) {
	die "Deactivate deactivates the current script, may not specify one.\n";
	# Future feature -- list and deactivate if specified script is
	# current.  That has a concurrency race condition and is not
	# conceivably useful, so ignored at least for the present.
}

# ######################################################################
# Start work; connect, start TLS, authenticate

my @host_port_pairs;

# Find the real hostname to connect to.
unless ($no_srv) {
	my $res = Net::DNS::Resolver->new();
	my $query = $res->query("_sieve._tcp.$server", 'SRV');
	my @srv_recs;
	if ($query) {
		foreach my $rr ($query->answer) {
			next unless $rr->type eq 'SRV';
			push @srv_recs, $rr;
		}
	}
	if (@srv_recs) {
		@srv_recs = Net::DNS::rrsort('SRV', '', @srv_recs);
		my $old = "[$server]:" . (defined $port ? $port : $DEFAULT_PORT);
		debug "dns: SRV results found for: $old";
		foreach my $rr (@srv_recs) {
			push @host_port_pairs, [$rr->target, $rr->port];
		}
	}

}

$port = $DEFAULT_PORT unless defined $port;
unless (@host_port_pairs) {
	push @host_port_pairs, [$server, $port];
}
my $sock = undef;

# Yes, this used to just try one connection and the list of candidates was
# bolted on; how could you tell?

foreach my $hp (@host_port_pairs) {
	my $host_candidate = $hp->[0];
	my $port_candidate = $hp->[1];
	debug "connection: trying <[$host_candidate]:$port_candidate>";
	my $s = IO::Socket::INET6->new(
		PeerHost	=> $host_candidate,
		PeerPort	=> $port_candidate,
		Proto		=> 'tcp',
		Domain		=> $net_domain,
		MultiHomed	=> 1, # try multiple IPs (IPv4 works, v6 doesn't?)
	);
	unless (defined $s) {
		my $extra = '';
		if ($!{EINVAL} and $net_domain != AF_UNSPEC) {
		  $extra = " (Probably no host record for overriden IP version)\n";
		}
		warn qq{Connection to <[$host_candidate]:$port_candidate> failed: $!\n$extra};
		next;
	}
	unless ($s->peerhost()) {
		# why am I seeing successful returns for unconnected sockets? *sigh*
		warn qq{Connection to <[$host_candidate]:$port_candidate> failed.\n};
		next;
	}
	$sock = $s;
	$server = $host_candidate;
	$port = $port_candidate;
	last;
}
exit(1) unless defined $sock;

$sock->autoflush(1);
debug "connection: remote host address is [@{[$sock->peerhost()]}] " .
	"port [@{[$sock->peerport()]}]";

my %capa;
my %raw_capabilities;
my %capa_dosplit = map {$_ => 1} qw( SASL SIEVE );
# Key is permissably empty keyword, value if defined is closure to call with
# capabilities after receiving complete list, for verifying permissability.
# First param $sock, second \%capa, third \%raw_capabilities
my %capa_permit_empty = (
	# draft 7 onwards clarify that empty SASL is permitted, but is error
	# in absense of STARTTLS
	SASL	=> sub {
		return if exists $_[1]{STARTTLS};
		# We die because there's no way to authenticate.
		# Spec states "This list can be empty if and only if STARTTLS
		# is also advertised" (section 1.7).
		closedie $_[0], "Empty SASL not permitted without STARTTLS\n";
		},
	SIEVE	=> undef,
);

sub parse_capabilities
{
	my $sock = shift;
	local %_ = @_;
	# Used under TLS to coerce EXTERNAL auth to be preferred:
	my $external_first = 0;
	$external_first = $_{external_first} if exists $_{external_first};

	my @double_checks;
	%raw_capabilities = ();
	%capa = ();
	while (<$sock>) {
		received unless /^OK\b/;
		chomp; s/\s*$//;
		if (/^OK\b/) {
			sget($sock, '-firstline', $_);
			last unless exists $_{sent_a_noop};
			# See large comment below in STARTTLS explaining the
			# resync problem to understand why this is here.
			my $end_tag = $_{sent_a_noop};
			unless (defined $end_tag and length $end_tag) {
				# In the initial NOOP-featuring draft, #10, we
				# got back 'NOOP'.  However, this was at odds
				# with the general syntax rules, so #11/#12
				# added the TAG response; with this, the
				# supplied NOOP parameter is returned in the
				# TAG response, but if there's no parameter
				# then there's just arbitrary server text.
				#
				# So where this used to use a default $end_tag
				# of 'NOOP', now we declare it a coding error
				# for this script to pass sent_a_noop without
				# a value consisting of the tag.
				closedie $sock, "Internal error: sent_a_noop without tag\n";
			}
			# Play crude, just look for the tag anywhere in the
			# response, honouring only word boundaries.  It's our
			# responsibility to make the tag long enough that this
			# works without tokenising.
			# Really, should check for: OK (TAG <tag-string>) text
			# where <tag-string> is "$end_tag" or {<len>}\r\n$end_tag
			if ($_ =~ m/\b\Q${end_tag}\E\b/) {
				return;
			}
			# Okay, that's the "server understands NOOP" case, for
			# which the server should have advertised the
			# capability prior to TLS (and so subject to
			# tampering); we play fast and loose, sending NOOP in
			# all cases, so have to cover the NO case below too;
			# the known instance of protocol violation we know of
			# is an older server waiting for client command after
			# TLS is up.  That server doesn't support NOOP.
			# Sending NOOP and expecting a NO response for the
			# unsupported command was the original technique used
			# by this code.
		} elsif (/^\"([^"]+)\"\s+\"(.*)\"$/) {
			my ($k, $v) = (uc($1), $2);
			unless (length $v) {
				unless (exists $capa_permit_empty{$k}) {
					warn "Empty \"$k\" capability spec not permitted: $_\n";
					# Don't keep the advertised capability unless
					# it has some value which is needed.  Eg,
					# NOTIFY must list a mechanism to be useful.
					next;
				}
				if (defined $capa_permit_empty{$k}) {
					push @double_checks, $capa_permit_empty{$k};
				}
			}
			if (exists $capa{$k}) {
				# won't catch if the first instance was ignored for an
				# impermissably empty value; by this point though we
				# would already have issued a warning and the server
				# is so fubar that it's not worth worrying about.
				warn "Protocol violation.  Already seen capability \"$k\".\n" .
					"Ignoring second instance and continuing.\n";
				next;
			}
			$raw_capabilities{$k} = $v;
			$capa{$k} = $v;
			if (exists $capa_dosplit{$k}) {
				$capa{$k} = [ split /\s+/, $v ];
			}
		} elsif (/^\"([^"]+)\"$/) {
			$raw_capabilities{$1} = '';
			$capa{$1} = 1;
		} elsif (/^NO\b/) {
			return if exists $_{sent_a_noop};
			warn "Unhandled server line: $_\n";
		} elsif (/^BYE\b(.*)/) {
			closedie_NOmsg $sock, $1,
				"Server said BYE when we expected capabilities.\n";
		} else {
			warn "Unhandled server line: $_\n";
		}
	};

	closedie $sock, "Server does not return SIEVE capability, unable to continue.\n"
		unless exists $capa{SIEVE};
	warn "Server does not return IMPLEMENTATION capability.\n"
		unless exists $capa{IMPLEMENTATION};

	foreach my $check_sub (@double_checks) {
		$check_sub->($sock, \%capa, \%raw_capabilities);
	}

	if (grep {lc($_) eq 'enotify'} @{$capa{SIEVE}}) {
		unless (exists $capa{NOTIFY}) {
			warn "enotify extension present, NOTIFY capability missing\n" .
				"This violates MANAGESIEVE specification.\n" .
				"Continuing anyway.\n";
		}
	}

	if (exists $capa{SASL} and $external_first
			and grep {uc($_) eq 'EXTERNAL'} @{$capa{SASL}}) {
		# We do two things.  We shift the EXTERNAL to the head of the
		# list, suggesting that it's the server's preferred choice.
		# We then mess around inside the Authen::SASL::Perl::EXTERNAL
		# private stuff (name starts with an underscore) to bump up
		# its priority -- for some reason, the method which is not
		# interactive and says "use information already available"
		# is less favoured than some others.
		debug "auth: shifting EXTERNAL to start of mechanism list";
		my @sasl = ('EXTERNAL');
		foreach (@{$capa{SASL}}) {
			push @sasl, $_ unless uc($_) eq 'EXTERNAL';
		}
		$capa{SASL} = \@sasl;
		$raw_capabilities{SASL} = join(' ', @sasl);
		no warnings 'redefine';
		$Authen::SASL::Perl::EXTERNAL::{_order} = sub { 10 };
	}
}
parse_capabilities $sock;

my $tls_bitlength = -1;

if (exists $capa{STARTTLS}) {
	ssend $sock, "STARTTLS";
	sget $sock;
	die "STARTTLS request rejected: $_\n" unless /^OK\s+\"/;
	IO::Socket::SSL->start_SSL($sock, %ssl_options) or do {
		my $e = IO::Socket::SSL::errstr();
		die "STARTTLS promotion failed: $e\n";
	};
	if (exists $main::{"Net::"} and exists $main::{"Net::"}{"SSLeay::"}) {
		my $t = Net::SSLeay::get_cipher_bits($sock->_get_ssl_object(), 0);
		$tls_bitlength = $t if defined $t and $t;
	}
	debug("--- TLS activated here [$tls_bitlength bits]");
	if ($dump_tls_information) {
		print $sock->dump_peer_certificate();
		if ($DEBUGGING and
		    exists $main::{"Net::"} and exists $main::{"Net::"}{"SSLeay::"}) {
			# IO::Socket::SSL depends upon Net::SSLeay
			# so this should be fairly safe, albeit messing
			# around behind IO::Socket::SSL's back.
			print STDERR Net::SSLeay::PEM_get_string_X509(
				$sock->peer_certificate());
		}
	}
	$forbid_clearauth = 0;
	# The current protocol spec says that the capability response must
	# be sent by the server after TLS is established by STARTTLS,
	# without the client issuing a request.  So after TLS,
	# server-goes-first.  The historical behaviour of Cyrus timseived
	# is the inverse; the server waits after TLS for the client to issue
	# CAPABILITY.  That historical behaviour is still what happens in
	# the current 'stable' release branch of Cyrus IMAP.
	# To accommodate both, we need to be able to resynchronise to
	# reality, so that we can get back to command-response.
	# We can't just check to see if there's data to read or not, since
	# that will break if the next data is delayed (race condition).
	# There was no protocol-compliant method to determine this, short
	# of "wait a while, see if anything comes along; if not, send
	# CAPABILITY ourselves".  So, I broke protocol by sending the
	# non-existent command NOOP, then scan for the resulting NO.
	# This at least is stably deterministic.  However, from draft 10
	# onwards, NOOP is a registered available extension which returns
	# OK.
	#
	# New problem: again, Cyrus timsieved.  As of 2.3.13, it drops the
	# connection for an unknown command instead of returning NO.  And
	# logs "Lost connection to client -- exiting" which is an interesting
	# way of saying "we dropped the connection".  At this point, I give up
	# on protocol-deterministic checks and fall back to version checking.
	# Alas, Cyrus 2.2.x is still widely deployed because 2.3.x is the
	# development series and 2.2.x is officially the stable series.
	# This means that if they don't support NOOP by 2.3.14, I have to
	# figure out how to decide what is safe and backtrack which version
	# precisely was the first to send the capability response correctly.
	my $use_noop = 1;
	if (exists $capa{"IMPLEMENTATION"} and
		$capa{"IMPLEMENTATION"} =~ /^Cyrus timsieved v2\.3\.(\d+)\z/ and
		$1 >= 13) {
		debug("--- Cyrus drops connection with dubious log msg if send NOOP, skip that");
		$use_noop = 0;
	}

	if ($use_noop) {
		my $noop_tag = "STARTTLS-RESYNC-CAPA";
		ssend $sock, qq{NOOP "$noop_tag"};
		parse_capabilities($sock,
			sent_a_noop	=> $noop_tag,
			external_first	=> $prioritise_auth_external);
	} else {
		parse_capabilities($sock,
			external_first	=> $prioritise_auth_external);
	}
	unless (scalar keys %capa) {
		ssend $sock, "CAPABILITY";
		parse_capabilities($sock,
			external_first => $prioritise_auth_external);
	}
} elsif ($forbid_clearchan) {
	die "TLS not offered, SASL confidentiality not supported in client.\n";
}

my %authen_sasl_params;
if ($DEBUGGING_SASL) {
	$authen_sasl_params{debug} = 15;
}
$authen_sasl_params{callback}{user} = $user;
if (defined $authzid) {
	$authen_sasl_params{callback}{authname} = $authzid;
}
if (defined $realm) {
	# for compatibility, we set it as a callback AND as a property (below)
	$authen_sasl_params{callback}{realm} = $realm;
}
my $prompt_for_password = sub {
	ReadMode('noecho');
	{ print STDERR "Sieve/IMAP Password: "; $| = 1; }
	my $password = ReadLine(0);
	ReadMode('normal');
	print STDERR "\n";
	chomp $password if defined $password;
	return $password;
};
if (defined $passwordfd) {
	open(PASSHANDLE, "<&=", $passwordfd)
		or die "Unable to open fd $passwordfd for reading: $!\n";
	my @data = <PASSHANDLE>;
	close(PASSHANDLE);
	chomp $data[-1];
	$authen_sasl_params{callback}{pass} = join '', @data;
} else {
	$authen_sasl_params{callback}{pass} = $prompt_for_password;
}

closedie($sock, "Do not have an authentication mechanism list\n")
	unless ref($capa{SASL}) eq 'ARRAY';
if (defined $authmech) {
	$authmech = uc $authmech;
	if (grep {$_ eq $authmech} map {uc $_} @{$capa{SASL}}) {
		debug "auth: will try requested SASL mechanism $authmech";
	} else {
		closedie($sock, "Server does not offer SASL mechanism $authmech\n");
	}
	$authen_sasl_params{mechanism} = $authmech;
} else {
	$authen_sasl_params{mechanism} = $raw_capabilities{SASL};
}

my $sasl = Authen::SASL->new(%authen_sasl_params);
die "SASL object init failed (local problem): $!\n"
	unless defined $sasl;

my $secflags = 'noanonymous';
$secflags .= ' noplaintext' if $forbid_clearauth;
my $authconversation = $sasl->client_new('sieve', $server, $secflags)
	or die "SASL conversation init failed (local problem): $!\n";
if ($tls_bitlength > 0) {
	$authconversation->property(externalssf => $tls_bitlength);
}
if (defined $realm) {
	$authconversation->property(realm => $realm);
}
{
	my $sasl_m = $authconversation->mechanism()
		or die "Oh why can't I decide which auth mech to send?\n";
	if ($sasl_m eq 'GSSAPI') {
		debug("-A- GSSAPI sasl_m <temp>");
		# gross hack, but it was bad of us to assume anything.
		# It also means that we ignore anything specified by the
		# user, which is good since it's Kerberos anyway.
		# (Major Assumption Alert!)
		$authconversation->callback(
			user => undef,
			pass => undef,
		);
	}

	my $sasl_tosend = $authconversation->client_start();
	if ($authconversation->code()) {
		my $emsg = $authconversation->error();
		closedie($sock, "SASL Error: $emsg\n");
	}

	if (defined $sasl_tosend and length $sasl_tosend) {
		my $mimedata = encode_base64($sasl_tosend, '');
		my $mlen = length($mimedata);
		ssend $sock, qq!AUTHENTICATE "$sasl_m" {${mlen}+}!;
		ssend $sock, $mimedata;
	} else {
		ssend $sock, qq{AUTHENTICATE "$sasl_m"};
	}
	sget $sock;

	while ($_ !~ /^(OK|NO)(?:\s.*)?$/m) {
		my $challenge;
		if (/^"(.*)"\r?\n?$/) {
			$challenge = $1;
		} else {
			unless (/^{(\d+)\+?}\r?$/m) {
				sfinish $sock, "*";
				closedie($sock, "Failure to parse server SASL response.\n");
			}
			($challenge = $_) =~ s/^{\d+\+?}\r?\n?//;
		}
		$challenge = decode_base64($challenge);

		my $response = $authconversation->client_step($challenge);
		if ($authconversation->code()) {
			my $emsg = $authconversation->error();
			closedie($sock, "SASL Error: $emsg\n");
		}
		$response = '' unless defined $response; # sigh
		my $senddata = encode_base64($response, '');
		my $sendlen = length $senddata;
		ssend $sock, "{$sendlen+}";
		# okay, we send a blank line here even for 0 length data
		ssend $sock, $senddata;
		sget $sock;
	}

	if (/^NO((?:\s.*)?)$/) {
		closedie_NOmsg($sock, $1, "Authentication refused by server\n");
	}
	if (/^OK\s+\(SASL\s+\"([^"]+)\"\)$/) {
		# This _should_ be present with server-verification steps which
		# in other profiles expect an empty response.  But Authen::SASL
		# doesn't let us confirm that we've finished authentication!
		# The assumption seems to be that the server only verifies us
		# so if it says "okay", we don't keep trying.
		my $final_auth = decode_base64($1);
		my $valid = $authconversation->client_step($final_auth);
		# With Authen::SASL before 2.11 (..::Perl 1.06),
		# Authen::SASL::Perl::DIGEST-MD5 module will complain at this
		# final step:
		#   Server did not provide required field(s): algorithm nonce
		# which is bogus -- it's not required or expected.
		# Authen::SASL 2.11 fixes this, with ..::Perl 1.06
		# We explicitly permit silent failure with the security
		# implications because we require a new enough version of
		# Authen::SASL at import time above and if someone removes
		# that check, then on their head be it.
		if ($authconversation->code()) {
			my $emsg = $authconversation->error();
			if ($Authen::SASL::Perl::VERSION >= 1.06) {
				closedie($sock, "SASL Error: $emsg\n");
			}
		}
		if (defined $valid and length $valid) {
			closedie($sock, "Server failed final verification [$valid]\n");
		}
	}

}

# ######################################################################
# We're in, we can do stuff.  What can we do?

sub sieve_list;
sub sieve_deactivate;
sub sieve_activate;
sub sieve_delete;
sub sieve_download;
sub sieve_upload;
sub sieve_checkscript;
sub localfs_ls;
sub localfs_chpwd;
sub localfs_pwd;
sub aux_quit;
sub aux_help;
sub aux_man;
sub aux_list_keywords;
sub complete_rl_sieve;
sub system_result;
sub tilde_expand ; # don't apply to cmdline params as shell does it for us

# Do *NOT* include any sort of shell-out.
# Basic local navigation and diagnostics yes; Yet Another ShellOut Cmd no.

# 'routine' => sub ref; invoked with $sock, params
# 'help' => help text
# 'action' => command-line --action
# 'alias' => extra name
# 'params' => count of parameters needed; -1 => any
# 'params_max' => if more parameters are _allowed_ than 'params'
#                 (last param is repeated if not this many)
# param list numbering: 1=first param, ...
# 'remote_name' => if there's a remote name, which position it comes
# 'local_name' => if there's a local name, which position it comes
# 'min_version' => require server to advertise this version for support
#                  (undef => "advertises VERSION capability")
my %sieve_commands = (
	help	=> { routine => \&aux_help, params => 0, help => 'this help' },
	'?'	=> { alias => 'help' },
	man	=> { routine => \&aux_man, params => 0, help => 'see docs' },
	quit	=> { routine => \&aux_quit, params => 0, help => 'goodbye!' },
	bye	=> { alias => 'quit' },
	logout	=> { alias => 'quit' },
	'exit'	=> { alias => 'quit' },
	list	=> {
		routine => \&sieve_list,
		help => 'list the scripts currently on the server',
		action => 1,
		params => 0,
	},
	ls	=> { alias => 'list' },
	dir	=> { alias => 'list' },
	lls	=> {
		routine => \&localfs_ls,
		help => 'local ls: look at local filesystem',
		params => 0,
		params_max => 1,
		local_name => 1,
	},
	lcd	=> {
		routine => \&localfs_chpwd,
		help => 'local cd: change local working directory',
		params => 0,
		params_max => 1,
		local_name => 1,
	},
	lpwd	=> {
		routine =>\&localfs_pwd,
		help => 'local pwd: show local working directory name',
		params => 0,
	},
	activate => {
		routine => \&sieve_activate,
		help => '<script> -- set the currently used script',
		action => 1,
		params => 1,
		remote_name => 1,
	},
	deactivate => {
		routine => \&sieve_deactivate,
		help => 'turn off sieve processing',
		action => 1,
		params => 0,
	},
	'delete' => {
		routine => \&sieve_delete,
		help => '<script> -- remove the script from the server',
		action => 1,
		params => 1,
		remote_name => 1,
	},
	rm	=> { alias => 'delete' },
	upload	=> {
		routine => \&sieve_upload,
		help => '<filename> [<scriptname>] -- put script on server',
		action => 1,
		params => 1,
		params_max => 2,
		local_name => 1,
		remote_name => 2,
	},
	checkscript  => {
		routine => \&sieve_checkscript,
		help => '<filename> -- check script on the server',
		action => 1,
		params => 1,
		local_name => 1,
		min_version => undef,
	},
	put	=> { alias => 'upload' },
	download => {
		routine => \&sieve_download,
		help => '<script> [<filename>] -- retrieve script from server',
		action => 1,
		params => 1,
		params_max => 2,
		remote_name => 1,
		local_name => 2,
	},
	get	=> { alias => 'download' },
	view	=> {
		routine => sub { sieve_download($_[0],$_[1],'-') },
		help => '<script> -- show contents of script',
		params => 1,
		remote_name => 1,
	},
	page	=> { alias => 'view' },
	more	=> { alias => 'view' },
	show	=> { alias => 'view' },
	echo	=> {
		hidden => 1,
		routine => sub { return unless @_ > 1;
			for (my $i=1; $i<=$#_; ++$i) { print "P$i : $_[$i]\n" }
		},
		params => -1,
	},
	keywords => {
		routine => \&aux_list_keywords,
		help => 'list %KEYWORD substitutions',
		params => 0,
	},
);

my %subst_patterns = (
	DATE		=> sub { return strftime '%Y-%m-%d', gmtime() },
	DATELOCAL	=> sub { return strftime '%Y-%m-%d', localtime() },
	TIME		=> sub { return strftime '%H:%M:%S', gmtime() },
	TIMELOCAL	=> sub { return strftime '%H:%M:%S', localtime() }, 
	DATETIME	=> sub { return strftime '%Y-%m-%dT%H:%M:%SZ', gmtime() },
	SERVER		=> $server,
	USER		=> $user,
	PORT		=> $port,
	RAND16		=> sub { return '' . int rand 65535 },
);

# ######################################################################
# Fix-up for optional stuff, where missing modules disable functionality.

my $have_needed_man_mods;
BEGIN {
	eval {
		my $mod = 'Pod::Simple::Text';
		my $mp = File::Spec->catfile(split(/::/, $mod));
		require "$mp.pm";
		import Pod::Simple::Text;
		$have_needed_man_mods = 1;
	};
}
unless ($have_needed_man_mods) {
	delete $sieve_commands{'man'};
}

# ######################################################################
# Fix-up for features missing in this server

unless ($ignore_server_version) {
	# If server does not advertise VERSION, it's missing certain features;
	# if it does, we can do min_version checks.
	# If our min_version is undef, we simply require any VERSION
	# RFC5804 defines VERSION as just a string "1.0" and says nothing
	# about comparison.  So for the time being, we'll go on "must look like
	# a number, optionally with a dot in it, and compares with Perl's
	# numerical operator" as a good-enough approach to predict the future.
	my $have_server_version = undef;
	if (exists $capa{VERSION}) {
		closedie($sock, "Unparsed server version [$capa{VERSION}]\n")
			unless $capa{VERSION} =~ /^[0-9]+(?:\.[0-9]+)?\z/;
		$have_server_version = $capa{VERSION};
	};

	my @kl = keys %sieve_commands;
	foreach my $k (@kl) {
		next unless exists $sieve_commands{$k}{min_version};
		my $min = $sieve_commands{$k}{min_version};
		unless (defined $have_server_version) {
			delete $sieve_commands{$k};
			next;
		}
		unless (defined $min) {
			next;
		}
		if ($min > $have_server_version) {
			delete $sieve_commands{$k};
			next;
		}
	}
}

# ######################################################################
# Do something

# Handle the case where everything is on the command-line.  No aliases
# apply, since GetOptions() sets $action for us.
# 
if ($action ne 'command-loop' and exists $sieve_commands{$action}{action}) {
	closedie $sock, "internal error, no routine for \'$action\'"
		unless exists $sieve_commands{$action}{routine};
	my @params;
	my $todo = $sieve_commands{$action};
	if (exists $todo->{local_name}) {
		closedie $sock, "Need a local sieve name\n"
			unless defined $localsievename;
		$params[$todo->{local_name}-1] = $localsievename;
	}
	if (exists $todo->{remote_name}) {
		closedie $sock, "Need a remote sieve name\n"
			unless defined $remotesievename;
		$params[$todo->{remote_name}-1] = $remotesievename;
	}
	$@ = '';
	eval { $todo->{routine}->($sock, @params) };
	my $saveddie = $@;
	sfinish $sock;
	if ($saveddie) {
		$saveddie =~ s/^QUIT:\n?//;
		die $saveddie if length $saveddie;
	}
	exit 0;
}

if ($action ne 'command-loop') {
	closedie $sock, "Internal error, don't recognise action \'$action\'";
}

# How to get commands, how to finish up.
my ($cmdlineget_func, $cmdlinedone_func);
my $report_lineno = 0;

if (defined $execscript) {
	$report_lineno = 1;
	my $scripth = new IO::File $execscript, '<'
		or closedie $sock, "Unable to read-open($execscript): $!\n";
	$cmdlineget_func = sub { return $scripth->getline() };
	$cmdlinedone_func = sub { $scripth->close() };

} else {
	eval {
		require Term::ReadLine;
		import Term::ReadLine;
		my $term = new Term::ReadLine 'sieve-connect';
		closedie $sock, "No terminal initialisation"
			unless defined $term;
		$term->ornaments(0);
		if ($term->ReadLine() =~ /::Gnu/) {
			# The relevant hooks aren't in the Perl implementation
			$term->Attribs->{completion_function} =
				sub { complete_rl_sieve($term, $sock, @_) };
			$term->Attribs->{completer_quote_characters} = '"';
			$term->Attribs->{filename_quote_characters} = " \t";
			$term->call_function('display-readline-version') if $DEBUGGING;
		}
		$cmdlineget_func = sub { return $term->readline('> ') };
		print STDERR "ReadLine support enabled.\n";
	};
	unless (defined $cmdlineget_func) {
		$cmdlineget_func = sub {
			print "> "; local $| = 1;
			my $l = <STDIN>;
			return $l;
		};
	}
}

my $exitval = 0;
my $lineno = 0;

while (defined (my $cmdline = $cmdlineget_func->())) {
	chomp $cmdline; $cmdline =~ s/^\s+//; $cmdline =~ s/\s+\z//;
	next unless length $cmdline;
	++$lineno;
	my $diag_prefix = "";
	if ($report_lineno) {
		$diag_prefix = "Line $lineno: ";
	}

	my @params;
	my ($cmd, $rest) = split /\s+/, $cmdline, 2;
	$cmd = lc $cmd;
	while (defined $rest and length $rest) {
		$rest =~ s/^\s+//;
		if ($rest =~ s/^"([^"]+)"\s*//) {
			push @params, $1;
			next;
		}
		if ($rest =~ s/(\S+)\s*//) {
			push @params, $1;
			next;
		}
		next unless length $rest;
		warn "${diag_prefix}Unable to parse rest of $cmd\n" .
			"Had {$cmdline}\nLeft {$rest}\n";
	}

	unless (exists $sieve_commands{$cmd}) {
		my @candidates = grep /^\Q$cmd\E/,
			grep {not exists $sieve_commands{$_}{hidden}}
				keys %sieve_commands;
		if (@candidates == 0) {
			warn "${diag_prefix}Unknown command: $cmd\n";
			next;
		} elsif (@candidates > 1) {
			@candidates = sort @candidates;
			warn "${diag_prefix}Which command?\n" .
				"That matches: @candidates\n";
			next;
		}
		$cmd = $candidates[0];
	}

	if (exists $sieve_commands{$cmd}{alias}) {
		$cmd = $sieve_commands{$cmd}{alias};
	}

	my $minp = $sieve_commands{$cmd}{params};
	my $maxp = exists $sieve_commands{$cmd}{params_max} ?
			$sieve_commands{$cmd}{params_max} : $minp;
	if ($maxp < $minp) {
		# don't die, we're not inside an eval{} so last is cleanest.
		warn "${diag_prefix}Internal configuration error, cmd $cmd max < min\n";
		last;
	}
	my $needtext;
	if ($minp == $maxp) {
		$needtext = "$minp parameters";
		$needtext =~ s/s\z// if $minp == 1;
		# I don't care about plurality and think encoding English rules
		# is unwise as people understand what's meant, but I don't
		# want bug reports about it.
	} else {
		$needtext = "at least $minp, at most $maxp, parameters";
	}

	if ($minp != -1 and (@params < $minp or @params > $maxp)) {
		warn "${diag_prefix}$cmd needs $needtext\n";
		next;
	}
	if ($minp != -1 and (@params != $maxp and @params)) {
		my $repeat = $params[-1];
		# When repeating it's assumed to be a filename.  There may
		# be an issue with putting a file from a different directory,
		# should take basename for repeats.  I can't think of a
		# situation where basename wouldn't be correct.
		$repeat = File::Basename::basename($repeat);
		for (my $i = $#params+1; $i <= $maxp; ++$i) {
			$params[$i] = $repeat;
		}
	}

	debug "Doing: $cmd @params";
	my $have_subst = 0;
	for (my $i=0; $i <= $#params; ++$i) {
		next unless defined $params[$i];
		next unless $params[$i] =~ /%/;
		my @cands = ($params[$i] =~ m/%([A-Z][A-Z0-9]*)/g);
		foreach my $c (sort {length($a) <=> length($b)} @cands) {
			next unless exists $subst_patterns{$c};
			my $replace = ref($subst_patterns{$c}) eq 'CODE' ?
				$subst_patterns{$c}->(
					cmd	=> $cmd,
					params	=> \@params,
					param	=> $params[$i],
					ind	=> $i,
					sock	=> $sock,
				)
				: $subst_patterns{$c};
			next if ref($replace);
			$params[$i] =~ s/%\Q$c\E/$replace/g;
			++$have_subst;
		}
	}
	if ($have_subst) {
		print "Command becomes: $cmd @params\n";
	}

	eval { $sieve_commands{$cmd}{routine}->($sock, @params) };
	if ($@ and $@ =~ /^QUIT:/) {
		(my $emsg = $@) =~ s/^QUIT:\n?//;
		if (length $emsg) {
			$exitval = 3;
			warn $emsg;
		}
		last;
	} elsif ($@) {
		warn $@;
	}
}

$cmdlinedone_func->() if defined $cmdlinedone_func;

sfinish $sock;
print "\n";
exit $exitval;

# ######################################################################
# The sieve commands.

# These may die, in which case it will be caught.
# They may not close the socket.
# If the die message starts QUIT: then a command-loop will abort too.

sub sieve_list
{
	my $sock = shift;
	ssend $sock, "LISTSCRIPTS";
	sget $sock;
	# These can also be literals, not quoted.  So this technically needs
	# to be reexpressed to a standard output format.  Let's just hope
	# no server ever does that.
	while (/^\"/) {
		print "$_\n";
		sget $sock;
	}
}

sub sieve_deactivate
{
	my $sock = shift;
	sieve_activate($sock, "");
}

sub sieve_activate
{
	my $sock = shift;
	my $scriptname = shift;
	ssend $sock, "SETACTIVE \"$scriptname\"";
	sget $sock;
	unless (/^OK((?:\s.*)?)$/) {
		warn "SETACTIVE($scriptname) failed: $_\n";
	}
}

sub sieve_delete
{
	my $sock = shift;
	my $delname = shift;
	ssend $sock, "DELETESCRIPT \"$delname\"";
	sget $sock;
	unless (/^OK((?:\s.*)?)$/) {
		warn "DELETESCRIPT($delname) failed: $_\n";
	}
}

sub sieve_download
{
	my ($sock, $remotefn, $localfn) = @_; splice @_, 0, 3;
	die "QUIT:Internal error, download missing remotefn\n"
		unless defined $remotefn;
	die "QUIT:Internal error, download missing localfn\n"
		unless defined $localfn;

	my $quotedremotefn = qq{"$remotefn"};
	if ($remotefn =~ /"/) {
		my $l = length $remotefn;
		$quotedremotefn = "{${l}+}\r\n$remotefn";
	}

	ssend $sock, qq{GETSCRIPT $quotedremotefn};
	sget $sock;
	if (/^NO((?:\s.*)?)$/) {
		die_NOmsg($1, qq{Script "$remotefn" not returned by server});
	}
	if (/^OK((?:\s.*)?)$/) {
		warn qq{Empty script "$remotefn"?  Not saved.\n};
		return;
	}
	unless (/^{(\d+)\+?}\r?$/m) {
		die "QUIT:Failed to parse server response to GETSCRIPT";
	}
	my $contentdata = $_;
	sget $sock;
	while (/^$/) { sget $sock; } # extra newline but only for GETSCRIPT?
	unless (/^OK((?:\s.*)?)$/) {
		die_NOmsg $_, "Script retrieval not successful, not saving";
	}
	my $fh;
	my $oldouthandle;
	unless ($localfn eq '-') {
		$fh = new IO::File tilde_expand($localfn), '>'
			or die "write-open($localfn) failed: $!\n";
		$oldouthandle = select $fh;
	}
	$contentdata =~ s/^{\d+\+?}\r?\n?//m;
	print $contentdata;
	select $oldouthandle if defined $oldouthandle;
	if (defined $fh) {
		$fh->close() or die "write-close($localfn) failed: $!\n";
	}
}

sub sieve_upload
{
	my ($sock, $localfn, $remotefn) = @_; splice @_, 0, 3;
	die "QUIT:Internal error, upload missing remotefn\n"
		unless defined $remotefn;
	die "QUIT:Internal error, upload missing localfn\n"
		unless defined $localfn;

	# I'm going to assume that any Sieve script will easily fit in memory.
	# Since Cyrus enforces admin-specified size constraints, this is
	# probably pretty safe.
	my $fh = new IO::File tilde_expand($localfn), '<'
		or die "aborting, read-open($localfn) failed: $!\n";
	my @scriptlines = $fh->getlines();
	$fh->close() or die "aborting, read-close($localfn failed: $!\n";

	my $len = 0;
	$len += length($_) foreach @scriptlines;

	my $quotedremotefn = qq{"$remotefn"};
	if ($remotefn =~ /"/) {
		my $l = length $remotefn;
		$quotedremotefn = "{${l}+}\r\n$remotefn";
	}

	ssend $sock, "PUTSCRIPT $quotedremotefn {${len}+}";
	ssend $sock, '-noeol', @scriptlines;
	ssend $sock, '';
	sget $sock;

	unless (/^OK((?:\s.*)?)$/) {
		warn "PUTSCRIPT($remotefn) failed: $_\n";
	}
}

sub sieve_checkscript
{
	my ($sock, $localfn) = @_; splice @_, 0, 2;
	die "QUIT:Internal error, check missing localfn\n"
	    unless defined $localfn;

	# I'm going to assume that any Sieve script will easily fit in memory.
	# Since Cyrus enforces admin-specified size constraints, this is
	# probably pretty safe.
	my $fh = new IO::File tilde_expand($localfn), '<'
		or die "aborting, read-open($localfn) failed: $!\n";
	my @scriptlines = $fh->getlines();
	$fh->close() or die "aborting, read-close($localfn failed: $!\n";

	my $len = 0;
	$len += length foreach @scriptlines;

	ssend $sock, "CHECKSCRIPT {${len}+}";
	ssend $sock, '-noeol', @scriptlines;
	ssend $sock, '';
	sget $sock;

	unless (/^OK((?:\s.*)?)$/) {
		warn "CHECKSCRIPT failed: $_\n";
	}
}

sub localfs_ls
{
	my ($sock, $localdir) = @_;
	unless (@cmd_localfs_ls) {
		warn "Misconfiguration: no local ls command available!\n";
		return;
	}
	my @cmd = @cmd_localfs_ls;
	push @cmd, tilde_expand $localdir
		if defined $localdir and length $localdir;
	system @cmd;
	return unless $?;
	warn system_result($?, $cmd[0]);
}

sub localfs_chpwd
{
	my ($sock, $localdir) = @_;
	unless (defined $localdir and length $localdir) {
		$localdir = '~';
	}
	$localdir = tilde_expand $localdir;
	chdir($localdir) or warn "chdir($localdir) failed: $!\n";
}

sub localfs_pwd
{
	print Cwd::cwd(), "\n";
}

sub aux_quit
{
	die "QUIT:\n"
}

sub aux_help
{
	my %aliases;
	my @commands;
	foreach (keys %sieve_commands) {
		next if exists $sieve_commands{$_}{hidden};
		if (exists $sieve_commands{$_}{routine}) {
			push @commands, $_;
		} elsif (exists $sieve_commands{$_}{alias}) {
			my $al = $sieve_commands{$_}{alias};
			$aliases{$al} = [] unless exists $aliases{$al};
			push @{$aliases{$al}}, $_;
		} else {
			debug "HELP what is item \'$_\'";
		}
	}
	# alignment, with ....
	my $maxlen = 0;
	foreach my $c (@commands) {
		my $l = length $c;
		$maxlen = $l if $l > $maxlen;
	}
	$maxlen += 4;
	my $indentspace = ' ' x $maxlen;
	$maxlen -= 2;

	foreach my $c (sort @commands) {
		print $c;
		if (exists $sieve_commands{$c}{help}) {
			print(' ', '.' x ($maxlen - length $c), ' ');
			print $sieve_commands{$c}{help};
		}
		print "\n";
		if (exists $aliases{$c}) {
			print $indentspace, 'aka: ',
				join(' ', sort @{$aliases{$c}}), "\n";
		}
	}
}

sub aux_man
{
	unless ($have_needed_man_mods) {
		print STDERR "Sorry, you're missing modules we need\n";
		return;
	}
	seek DATA, $DATASTART, 0;
	my $parser = Pod::Simple::Text->new();
	$parser->no_whining(1);
	$parser->output_fh(*STDOUT);
	$parser->parse_file(*DATA);
}

sub aux_list_keywords
{
	print "Command parameters may have these \%KEYWORD patterns:\n";
	print "\t\%$_\n" foreach sort keys %subst_patterns;
}

# ######################################################################
# Term::ReadLine support.

sub complete_rl_sieve
{
	my ($term, $sock, $text, $line, $start) = @_;

	if ($start == 0) {
		my $c = lc $text;
		return grep /^\Q$c\E/,
			grep {not exists $sieve_commands{$_}{hidden}}
				keys %sieve_commands;
	}

	my $rl_attribs = $term->Attribs;
	my $quote = $rl_attribs->{completion_quote_character};
	$quote = '' if $quote eq "\0";

	my $prefix = substr($line, 0, $start);
	my @previous_words = ($prefix =~ m!((?:"[^"]+")|\S+)!g);

	my $conf = $sieve_commands{lc $previous_words[0]};
	$conf = $sieve_commands{$conf->{alias}} if exists $conf->{alias};
	my $maxp = exists $conf->{params_max} ? $conf->{params_max} : (
		exists $conf->{params} ? $conf->{params} : 0 );

	return () unless $maxp; # no parameters allow;

	my $position = scalar @previous_words;
	--$position if substr($line, $start-1, 1) eq $quote; # *sigh*

	# we only assist if it starts; too icky otherwise
	if ($text =~ m!^(.*)%((?:[A-Z][A-Z0-9]*)?)\z!) {
		my ($before, $sofar) = ($1, $2);
		my @matches = grep /^\Q$sofar\E/, keys %subst_patterns;
		map {s/^/${before}\%/} @matches;
		return @matches;
	}

	if (exists $conf->{remote_name}
		and $conf->{remote_name} == $position) {

		$rl_attribs->{filename_completion_desired} = 1;
		local $_;
		my @matches;
		my $textmatch = qr/^\Q$text\E/;
		ssend $sock, "LISTSCRIPTS";
		sget $sock;
		while (/^"(.+)"[^"]*\r?\n?$/) {
			my $c = $1;
			push @matches, $c if $c =~ $textmatch;
			sget $sock;
		}
		return @matches;

	} elsif (exists $conf->{local_name}
		and $conf->{local_name} == $position) {

		$rl_attribs->{filename_completion_desired} = 1;
		unless ($text =~ /^~/) {
			return <$text*>;
		}
		if ($text =~ m!^~[^/]+\z!) {
			setpwent;
			my @users;
			while (defined (my $u = getpwent)) {
				push @users, $u if $u =~ /^\Q$user\E/;
			}
			map {s/^/~/} @users;
			return @users;
		}
		my ($t2, $user, $home) = tilde_expand($text, 1);
		my @completes = <$t2*>;
		map {s/^\Q$home\E/~$user/} @completes;
		return @completes;

	} else {
		return ();
	}
}

# ######################################################################
# minor routines

sub debug
{
	return unless $DEBUGGING;
	print STDERR "$_[0]\n";
}

sub diag {
	my ($prefix, $data) = @_;
	$data =~ s/\r/\\r/g; $data =~ s/\n/\\n/g; $data =~ s/\t/\\t/g;
	$data =~ s/([^[:graph:] ])/sprintf("%%%02X", ord $1)/eg;
	debug "$prefix $data";
}
sub sent { my $t = defined $_[0] ? $_[0] : $_; diag('>>>', $t) }
sub received { my $t = defined $_[0] ? $_[0] : $_; diag('<<<', $t) }

sub ssend
{
	my $sock = shift;
	my $eol = "\r\n";
	if (defined $_[0] and $_[0] eq '-noeol') {
		shift;
		$eol = '';
	}
	foreach my $l (@_) {
		$sock->print("$l$eol");
# yes, the debug output can have extra blank lines if supplied -noeol because
# they're already present.  Rather than mess around to tidy it up, I'm leaving
# it because it's debug output, not UI or protocol text.
		sent "$l$eol";
	}
}

sub sget
{
	my $sock = shift;
	my $l = undef;
	my $dochomp = 1;
	while (@_) {
		my $t = shift;
		next unless defined $t;
		if ($t eq '-nochomp') { $dochomp = 0; next; }
		if ($t eq '-firstline') {
			die "Missing sget -firstline parameter"
				unless defined $_[0];
			$l = $_[0];
			shift;
			next;
		}
		die "Unknown sget parameter [$t]";
	}
	$l = $sock->getline() unless defined $l;
	unless (defined $l) {
		debug "... no line read, connection dropped?";
		die "Connection dropped unexpectedly when trying to read.\n";
	}
	if ($l =~ /{(\d+)\+?}\s*\n?\z/) {
		debug "... literal string response, length $1";
		my $len = $1;
		if ($len == 0) {
			my $discard = $sock->getline();
		} else {
			while ($len > 0) {
				my $extra = $sock->getline();
				$len -= length($extra);
				$l .= $extra;
			}
		}
		$dochomp = 0;
	}
	received $l;
	if ($dochomp) {
		chomp $l; $l =~ s/\s*$//;
	}
	if (defined wantarray) {
		return $l;
	} else {
		$_ = $l;
	}
}

sub sfinish
{
	my $sock = shift;
	if (defined $_[0]) {
		ssend $sock, $_[0];
		sget $sock;
	}
	ssend $sock, "LOGOUT";
	sget $sock;
}

sub closedie
{
	my $sock = shift;
	my $e = $!;
	sfinish($sock);
	$! = $e;
	die @_;
}

sub closedie_NOmsg
{
	my $sock = shift;
	my $suffix = shift;
	if (length $suffix) {
		$suffix = ':' . $suffix;
	} else {
		$suffix = '.';
	}
	closedie($sock, $_[0] . $suffix . "\n");
}

sub die_NOmsg
{
	my $suffix = shift;
	my $msg = shift;
	if (length $suffix) {
		$msg .= ':' . $suffix . "\n";
	} else {
		$msg .= ".\n";
	}
	die $msg;
}

sub system_result
{
	my ($ret, $cmd) = @_;
	$cmd = 'the command' unless defined $cmd;
	return "" unless $ret;
	my ($ex, $sig, $core) = ($ret >> 8, $ret & 127, $ret & 128);
	my $msg = "$cmd died";
	$msg .= ", exiting $ex"		if $ex;
	$msg .= ", signal $sig"		if $sig;
	$msg .= ' (core dumped)'	if $core;
	return "$msg\n";
}

sub tilde_expand
{
	my $path = $_[0];
	my $more = defined $_[1] ? $_[1] : 0;
	return $path unless $path =~ /^~/;
# No File::Spec because ~ is Unix-specific, AFAIK.

	$path =~ m!^~([^/]*)!;
	my $tilded = $1;
	my $user = length $1 ? $1 : scalar getpwuid $>;
	return $path unless defined $user; # non-Unix?
	my $home = (getpwnam($user))[7];
	$path =~ s{^~([^/]*)}{$home};
# don't be context-sensitive unless asked for, as it's more useful in
# IO::File constructors this way.
	return ($more and wantarray) ? ($path, $tilded, $home) : $path;
}

# ######################################################################
__END__

=head1 NAME

sieve-connect - managesieve command-line client

=head1 SYNOPSIS

 sieve-connect [-s <hostname>] [-p <portspec>] [-u <user>] [a <authzid>]
               [-m <authmech>] [-r realm] [-e execscript]
	       [... longopts ...]
 sieve-connect [--localsieve <script>] [--remotesieve <script>]
	       [--debug] [--dumptlsinfo]
               [--server <hostname>] [--port <portspec>] [--4|--6]
	       [--user <authentication_id>] [--authzid <authzid>]
	       [--realm <realm>] [--passwordfd <n>]
	       [--clientkey <file> --clientcert <file>]|[--clientkeycert <file>]
	       [--notlsverify|--nosslverify]
	       [--noclearauth] [--noclearchan]
	       [--authmech <mechanism>]
	       [--ignoreserverversion]
	       [--upload|--download|--list|--delete|--check
	        --activate|--deactivate]|[--exec <script>]
	       [--help|--man]

=head1 DESCRIPTION

B<sieve-connect> is a client for the C<MANAGESIEVE> protocol, which is
an Internet Draft protocol for manipulation of C<Sieve> scripts in a
repository.
More simply, B<sieve-connect> lets you control your mail-filtering
rule files on a mail server.

B<sieve-connect> can be invoked with an action from the command-line
to make it easy to script one-shot actions, it can be provided with
a script file or it can be left to enter an interactive command-loop,
where it supports tab-completion (if the supporting Perl module is
available) and basic navigation of the local
file-system in the style of C<FTP> clients.

B<sieve-connect> supports the use of C<TLS> via the C<STARTTLS> command,
including authentication via client certificates.
C<sieve-connect> also supports whichever C<SASL> mechanisms your
F<Authen::SASL::Perl> library provides, as long as they do not require
SASL protection layers.

In Interactive mode, a C<help> command is available.  Command parameters
with a C<%> in them are examined to see if they match C<%KEYWORD>, where
C<KEYWORD> is always in upper-case.  The list of keywords may be retrieved
with the C<keywords> command and includes items such as C<%DATE>, C<%USER>,
etc.

=head1 OPTIONS

The remote sieve script name defaults to the same as the local sieve
script name, so just specify the local one if only one is needed; it
was a deliberate decision to have the defaults this way around, to make
people think about names in the local filesystem.  There is no default
script name.

The B<--debug> option turns on diagnostic traces.
The B<--debugsasl> option asks the SASL library for debugging.
The B<--dumptlsinfo> shows the TLS (SSL) peer information; if specified
together with B<--debug> then the server's PEM certificate will be
provided as debug trace.

The B<--version> option shows version information.
When combined with B<--debug> it will show implementation dependency versions.

The server can be a host or IP address, IPv4 or IPv6;
the default is C<$IMAP_SERVER> from the environment (if it's not a
unix-domain socket path) with any port specificaion stripped off,
else F<localhost>.
The port can be any Perl port specification, default is F<sieve(4190)>.
The B<--4> or B<--6> options may be used to coerce IPv4 or IPv6.

By default, the server is taken to be a domain, for which SRV records are
looked up; use B<--nosrv> to inhibit SRV record lookup.

The B<--user> option will be required unless you're on a Unix system
with getpwuid() available and your Cyrus account name matches your system
account name.  B<--authmech> can be used to force a particular authentication
mechanism.  B<--authzid> can be used to request authorisation to act as
the specified id.
B<--realm> can be used to try to pass realm information to the authentication
mechanism.
If you want to provide a password programmatically,
use B<--passwordfd> to state which file descriptor (typically F<0>)
the password can be read from.
Everything until the newline before EOF is the password,
so it can contain embedded newlines.  Do not provide passwords on a
command-line or in a process environment.

If you are willing to accept the risk of man-in-the-middle active attacks
and you are unable to arrange for the relevant Certificate Authority
certificate to be available, then you can lower your safety with the
B<--notlsverify> option, also spelt B<--nosslverify>.

For SSL client certificate authentication, either B<--clientkeycert> may
be used to refer to a file with both the key and cert present or both
B<--clientkey> and B<--clientcert> should point to the relevant files.
The data should be in PEM file-format.

The B<--noclearauth> option will prevent use of cleartext authentication
mechanisms unless protected by TLS.  The B<--noclearchan> option will
mandate use of some confidentiality layer; at this time only TLS is
supported.

By default, the server's "VERSION" capability will be used to filter the
commands available.  Use B<--ignoreserverversion> to prevent this.

The remaining options denote actions.  One, and only one, action may be
present.  If no action is present, the interactive mode is entered.
If the exec action is present, commands are read from the script
instead.

It is believed that the names of the actions are
sufficiently self-descriptive for any English-speaker who can safely be
allowed unaccompanied computer usage.

(If B<--server> is not explicitly stated, it may be provided at the end of
the command-line for compatibility with sieveshell.)

=head1 ENVIRONMENT

C<$IMAP_SERVER> for a default IMAP server.  C<$USERNAME> and C<$LOGNAME>
where the C<getpwuid()> function is not available.

=head1 BUGS

If the authentication protocol negotiates a protection layer then things
will rapidly Go Bad.  A mitigating factor is that no protection layer
should be negotiated whilst under STARTTLS protection.  Just use TLS!

When listing scripts, the format is based upon the raw server output,
assuming that the server uses quoted-strings for the script names.  The
output is just passed back on the basis that it's a fairly good interface
to pass to a program.  But a server could choose to use literal strings,
even though the results are defined as line-break separated -- that would
mean that some linebreaks are special.  Hopefully no server will do this.

If B<sieve-connect> fails to connect to an IPv4 server without the B<-4>
option being explicitly passed, then you've encountered a portability
issue in the F<IO::Socket::INET6> Perl library and need to upgrade that.

Most historical implementations used port 2000 for ManageSieve.  RFC5804
allocates port 4190.  This tool uses a port-spec of "sieve(4190)" as the
default port, which means that an /etc/services (or substitute) entry for
"sieve" as a TCP service takes precedence, but if that is not present, to
assume 4190 as the default.  This change means that if you're still using
port 2000 and do not have an /etc/services entry, updating to/beyond release
0.75 of this tool will break invocations which do not specify a port.  The
specification of the default port was moved to the user-configurable section
at the top of the script and administrators may wish to override the shipped
default.  You can bypass all of this mess by publishing SRV records,
per RFC5804.

The Net::DNS Perl module does not (at time of writing) provide full support for
weighted prioritised SRV records and I have not made any effort to fix this;
whatever the default sort algorithm provides for SRV is what is used for
ordering.

=head1 NON-BUGS

Actually uses STARTTLS.  Can handle script names with embedded whitespace.
Author needs access to a server which handles embedded quote characters
properly to complete testing of that.

=head1 HISTORY

B<sieve-connect> was written as a demonstration for the C<info-cyrus>
mailing-list, 2006-11-14.  It was a single-action-and-quit script for
scripting purposes.  The command-loop code was written (two days) later
and deliberately designed to be compatible with sieveshell.

=head1 AUTHOR

Phil Pennock E<lt>phil-perl@spodhuis.orgE<gt> is guilty, m'Lud.

=head1 PREREQUISITES

Perl.  F<Authen::SASL>.  F<IO::Socket::INET6>.
F<IO::Socket::SSL> (at least version 0.97).  F<Pod::Usage>.
F<Net::DNS> for SRV lookup.
F<Pod::Simple::Text> for built-in man command (optional).
F<Term::ReadKey> to get passwords without echo.
Various other Perl modules which are believed to be standard.
F<Term::ReadLine> will significantly improve interactive mode.
F<Term::ReadLine::Gnu> will improve it further by allowing tab-completion.

=head1 INTEROPERABILITY

B<sieve-connect> is regularly tested with the B<timsieved> server
distributed with the Cyrus IMAP server.  Further interoperability
testing is underway, more is desired (test accounts appreciated!).

=cut
