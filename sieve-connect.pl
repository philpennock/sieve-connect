#!/usr/bin/perl
#
# $HeadURL$
#
# timsieved client script
#
# Copyright © 2006, 2007 Phil Pennock.  All rights reserved.
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

my %ssl_options = (
	SSL_version	=> 'TLSv1',
	SSL_cipher_list	=> 'ALL:!NULL:!LOW:!EXP:!ADH:@STRENGTH',
	SSL_verify_mode	=> 0x01,
	SSL_ca_path	=> '/etc/ssl/certs',
);

my @cmd_localfs_ls = qw( ls -C );

# ######################################################################
# No user-serviceable parts below

use Authen::SASL qw(Perl); # Need a way to ask which mechanism to send
use Authen::SASL::Perl::EXTERNAL; # We munge inside its private stuff.
use Cwd qw();
use Errno;
use Getopt::Long;
use IO::File;
use IO::Socket::INET6;
use IO::Socket::SSL 0.97; # SSL_ca_path bogus before 0.97
use MIME::Base64;
use Pod::Usage;
use POSIX qw/ strftime /;
use Term::ReadKey;
# interactive mode will attempt to pull in Term::ReadLine too.

sub debug;
sub sent;
sub ssend;
sub sget;
sub sfinish;
sub received;
sub closedie;
sub closedie_NOmsg;
sub die_NOmsg;

my $DEBUGGING = 0;
my $DATASTART = tell DATA;
my $localsievename;
my $remotesievename;
my ($user, $authzid, $authmech, $sslkeyfile, $sslcertfile, $passwordfd);
my $prioritise_auth_external = 0;
my ($server, $realm);
my $port = 'sieve(2000)';
my $net_domain = AF_UNSPEC;
my $action = 'command-loop';
my $execscript;
GetOptions(
	"localsieve=s"	=> \$localsievename,
	"remotesieve=s"	=> \$remotesievename,
	"server|s=s"	=> \$server,
	"port|p=s"	=> \$port, # not num, allow service names
	"user|u=s"	=> \$user,
	"realm|r=s"	=> \$realm,
	"authzid|authname|a=s"	=> \$authzid, # authname for sieveshell compat
	"authmech|m=s"	=> \$authmech,
	"passwordfd=n"	=> \$passwordfd,
	"clientkey=s"	=> \$sslkeyfile,
	"clientcert=s"	=> \$sslcertfile,
	"clientkeycert=s" => sub { $sslkeyfile = $sslcertfile = $_[1] },
	"4"		=> sub { $net_domain = AF_INET },
	"6"		=> sub { $net_domain = AF_INET6 },
	"debug"		=> \$DEBUGGING,
	# option names can be short-circuited, $action is complete:
	"upload"	=> sub { $action = 'upload' },
	"download"	=> sub { $action = 'download' },
	"list"		=> sub { $action = 'list' },
	"delete"	=> sub { $action = 'delete' },
	"activate"	=> sub { $action = 'activate' },
	"deactivate"	=> sub { $action = 'deactivate' },
	"exec|e=s"	=> sub { $execscript = $_[1]; $action='command-loop' },
	'help|?'	=> sub { pod2usage(0) },
	'man'		=> sub { pod2usage(-exitstatus => 0, -verbose => 2) },
) or pod2usage(2);
# We don't implement HAVESPACE <script> <size>

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
	unless $server =~ /^[A-Za-z0-9_.-]+\z/;
die "Bad port specification\n"
	unless $port =~ /^[A-Za-z0-9_()-]+\z/;

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

if (defined $localsievename and $action eq 'upload') {
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

my $sock = IO::Socket::INET6->new(
	PeerHost	=> $server,
	PeerPort	=> $port,
	Proto		=> 'tcp',
	Domain		=> $net_domain,
);
unless (defined $sock) {
	my $extra = '';
	if ($!{EINVAL} and $net_domain != AF_UNSPEC) {
	  $extra = " (Probably no host record for overriden IP version)\n";
	}
	die qq{Connection to "$server" [port $port] failed: $!\n$extra};
}

$sock->autoflush(1);
debug "connection: remote host address is @{[$sock->peerhost()]}";

my %capa;
my %raw_capabilities;
my %capa_dosplit = map {$_ => 1} qw( SASL SIEVE );

sub parse_capabilities
{
	my $sock = shift;
	my $external_first = shift;
	$external_first = 0 unless defined $external_first;

	%raw_capabilities = ();
	%capa = ();
	while (<$sock>) {
		chomp; s/\s*$//;
		received;
		last if /^OK$/;
		if (/^\"([^"]+)\"\s+\"(.+)\"$/) {
			my ($k, $v) = ($1, $2);
			$raw_capabilities{$k} = $v;
			$capa{$k} = $v;
			if (exists $capa_dosplit{$k}) {
				$capa{$k} = [ split /\s+/, $v ];
			}
		} elsif (/^\"([^"]+)\"$/) {
			$raw_capabilities{$1} = '';
			$capa{$1} = 1;
		} else {
			warn "Unhandled server line: $_\n"
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

if (exists $capa{STARTTLS}) {
	ssend $sock, "STARTTLS";
	sget $sock;
	die "STARTTLS request rejected: $_\n" unless /^OK\s+\"/;
	IO::Socket::SSL->start_SSL($sock, %ssl_options) or do {
		my $e = IO::Socket::SSL::errstr();
		die "STARTTLS promotion failed: $e\n";
	};
	debug("--- TLS activated here");
	ssend $sock, "CAPABILITY";
	parse_capabilities($sock, $prioritise_auth_external);
}

my %authen_sasl_params;
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

my $authconversation = $sasl->client_new('sieve', $server, '')
	or die "SASL conversation init failed (local problem): $!\n";
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
				die $sock, "Failure to parse server SASL response.\n";
			}
			($challenge = $_) =~ s/^{\d+\+?}\r?\n?//;
		}
		$challenge = decode_base64($challenge);

		my $response = $authconversation->client_step($challenge);
		$response = '' unless defined $response; # sigh
		my $senddata = encode_base64($response, '');
		my $sendlen = length $senddata;
		ssend $sock, "{$sendlen+}";
		# okay, we send a blank line here even for 0 length data
		ssend $sock, $senddata;
		sget $sock;
	}

	if (/^NO((?:\s.*)?)$/) {
		closedie_NOmsg($sock, $1, "Authentication refused by server");
	}
	if (/^OK\s+\(SASL\s+\"([^"]+)\"\)$/) {
		# This _should_ be present with server-verification steps which
		# in other profiles expect an empty response.  But Authen::SASL
		# doesn't let us confirm that we've finished authentication!
		# The assumption seems to be that the server only verifies us
		# so if it says "okay", we don't keep trying.
		my $final_auth = decode_base64($1);
		my $valid = $authconversation->client_step($final_auth);
		if (defined $valid and length $valid) {
			closedie($sock, "Server failed final verification");
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
		$term->Attribs->{completion_function} =
			sub { complete_rl_sieve($term, $sock, @_) };
		$term->Attribs->{completer_quote_characters} = '"';
		$term->Attribs->{filename_quote_characters} = " \t";
		$cmdlineget_func = sub { return $term->readline('> ') };
		print STDERR "ReadLine support enabled.\n";
	};
	unless (defined $cmdlineget_func) {
		$cmdlineget_func = sub {
			print "> "; $| = 1;
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
	unless (/^{(\d+)}\r?$/m) {
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
				join(' ', @{$aliases{$c}}), "\n";
		}
	}
}

sub aux_man
{
	use Pod::Text;
	seek DATA, $DATASTART, 0;
	my $parser = Pod::Text->new();
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

sub sent { $_[0] = $_ unless defined $_[0]; debug ">>> $_[0]"; }
sub received { $_[0] = $_ unless defined $_[0]; debug "<<< $_[0]"; }

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
		sent $l;
	}
}

sub sget
{
	my $sock = shift;
	my $dochomp = 1;
	$dochomp = 0 if defined $_[0] and $_[0] eq '-nochomp';
	my $l;
	$l = $sock->getline();
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
	if ($dochomp) {
		chomp $l; $l =~ s/\s*$//;
	}
	received $l;
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

sieve-connect -- managesieve command-line client

=head1 SYNOPSIS

 sieve-connect [-s <hostname>] [-p <portspec>] [-u <user>] [a <authzid>]
               [-m <authmech>] [-r realm] [-e execscript]
	       [... longopts ...]
 sieve-connect [--localsieve <script>] [--remotesieve <script>]
	       [--debug]
               [--server <hostname>] [--port <portspec>] [--4|--6]
	       [--user <authentication_id>] [--authzid <authzid>]
	       [--realm <realm>] [--passwordfd <n>]
	       [--clientkey <file> --clientcert <file>]|
	        [--clientkeycert <file>]
	       [--authmech <mechanism>]
	       [--upload|--download|--list|--delete|
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

The server can be a host or IP address, IPv4 or IPv6;
the default is C<$IMAP_SERVER> from the environment (if it's not a
unix-domain socket path) with any port specificaion stripped off,
else F<localhost>.
The port can be any Perl port specification, default is F<sieve(2000)>.
The B<--4> or B<--6> options may be used to coerce IPv4 or IPv6.

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

For SSL client certificate authentication, either B<--clientkeycert> may
be used to refer to a file with both the key and cert present or both
B<--clientkey> and B<--clientcert> should point to the relevant files.
The data should be in PEM file-format.

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
F<Term::ReadKey> to get passwords without echo.
Various other Perl modules which are believed to be standard.
F<Term::ReadLine> will significantly improve interactive mode.
F<Term::ReadLine::Gnu> will improve it further by allowing tab-completion.

=head1 INTEROPERABILITY

B<sieve-connect> is regularly tested with the B<timsieved> server
distributed with the Cyrus IMAP server.  Further interoperability
testing is underway, more is desired (test accounts appreciated!).

=cut
