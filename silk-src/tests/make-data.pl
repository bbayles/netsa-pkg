#! /usr/bin/perl -w
#
#######################################################################
## Copyright (C) 2009-2023 by Carnegie Mellon University.
##
## @OPENSOURCE_LICENSE_START@
##
## SiLK 3.22.0
##
## Copyright 2023 Carnegie Mellon University.
##
## NO WARRANTY. THIS CARNEGIE MELLON UNIVERSITY AND SOFTWARE ENGINEERING
## INSTITUTE MATERIAL IS FURNISHED ON AN "AS-IS" BASIS. CARNEGIE MELLON
## UNIVERSITY MAKES NO WARRANTIES OF ANY KIND, EITHER EXPRESSED OR IMPLIED,
## AS TO ANY MATTER INCLUDING, BUT NOT LIMITED TO, WARRANTY OF FITNESS FOR
## PURPOSE OR MERCHANTABILITY, EXCLUSIVITY, OR RESULTS OBTAINED FROM USE OF
## THE MATERIAL. CARNEGIE MELLON UNIVERSITY DOES NOT MAKE ANY WARRANTY OF
## ANY KIND WITH RESPECT TO FREEDOM FROM PATENT, TRADEMARK, OR COPYRIGHT
## INFRINGEMENT.
##
## Released under a GNU GPL 2.0-style license, please see LICENSE.txt or
## contact permission@sei.cmu.edu for full terms.
##
## [DISTRIBUTION STATEMENT A] This material has been approved for public
## release and unlimited distribution.  Please see Copyright notice for
## non-US Government use and distribution.
##
## GOVERNMENT PURPOSE RIGHTS - Software and Software Documentation
##
## Contract No.: FA8702-15-D-0002
## Contractor Name: Carnegie Mellon University
## Contractor Address: 4500 Fifth Avenue, Pittsburgh, PA 15213
##
## The Government's rights to use, modify, reproduce, release, perform,
## display, or disclose this software are restricted by paragraph (b)(2) of
## the Rights in Noncommercial Computer Software and Noncommercial Computer
## Software Documentation clause contained in the above identified
## contract. No restrictions apply after the expiration date shown
## above. Any reproduction of the software or portions thereof marked with
## this legend must also reproduce the markings.
##
## Carnegie Mellon(R) and CERT(R) are registered in the U.S. Patent and
## Trademark Office by Carnegie Mellon University.
##
## This Software includes and/or makes use of Third-Party Software each
## subject to its own license.
##
## DM23-0973
##
## @OPENSOURCE_LICENSE_END@
#######################################################################
#  make-data.pl
#
#    This script generates textual output that can be feed to rwtuc to
#    create flow records suitable for testing many of the analysis
#    tools in the SiLK suite.
#
#    For the --ipv4-output, the "internal" IP space is taken as
#    192.168.0.0/16.  There are two "external" spaces: 10.0.0.0/8 is
#    the majority of the external space; 172.16.0.0/12 holds services
#    the internal network relies on (NTP, DNS, DHCP).
#
#    Data includes NTP, DNS, DHCP, ICMP, HTTP, SMTP, SSH
#
#    Data covers a 3 day period:
#    Feb 12 00:00:00 2009 --- Feb 14 23:59:59 2009 UTC
#
#    The --ipv6-output differs from the IPv4 output only in the
#    following with ways:
#
#    * The source and destination IP addresses are each modified as
#      follows:
#
#      w.x.y.z ==> 2001:db8:w:x::y:z
#
#    * Protocol 1 is changed to protocol 58.
#
#
#    IPs and ephemeral ports are created by taking the natural log of
#    values from rand(), which should allow tools like rwstats to find
#    reasonable "noisy" talkers.
#
#  Mark Thomas
#  March 2009
#######################################################################
#  RCSIDENT("$SiLK: make-data.pl b2b562f1ea39 2023-02-20 17:50:25Z mthomas $")
#######################################################################

use strict;
use Getopt::Long qw(GetOptions);
use Socket;

our $STATUS_DOTS = 0;
our $COLUMNAR = 0;
our @FIELDS = ();
our $MAX_RECORDS = 0;
our $IPV6_ADDED_WIDTH = 7;

our $IPV4_OUTPUT;
our $IPV6_OUTPUT;
our $PDU_OUTPUT;
our $PDU_HOST_PORT;

# true if --pdu-4network was specified (use IPv4-only)
our $PDU_IPV4;

# true if --pdu-6network was specified (use IPv6-only)
our $PDU_IPV6;


# the hash keys for each field
our @FIELD_KEYS    = qw(sip dip sport dport proto
                        packets bytes stime dur
                        sensor class type input output application
                        init_flags sess_flags attributes);

# the printed title for each field; also used to parse field list
our @FIELD_NAMES   = qw(sIP dIP sPort dPort protocol
                        packets bytes sTime dur
                        sensor class type in out application
                        initialFlags sessionFlags attributes);

# the width of each field for columnar output
our @FIELD_WIDTHS  = qw(10 10 5 5 3
                        10 10 14 9
                        3 3 7 5 5 5
                        8 8 8);

# the format used to print each field
our @FIELD_FORMATS = qw(%s %s %u %u %u
                        %u %u %u.%03d %d.%03d
                        %s %s %s %u %u %u
                        %s %s %s);

# Seed used to initialize the pseudo-random number generator
my $SRAND_SEED = 18272728;

# Maximum time step to use
my $TIMESTEP_MAX = 3250;

# Thu Feb 12 00:00:00 2009 UTC
my $start_date = 1234396800;

# Sat Feb 14 23:59:59 2009
my $end_date = 1234655999;

# the internal network is 192.168.0.0/16
my $int_offset = (192 << 24) | (168 << 16);

# the external network is 10.0.0.0/8
my $ext_offset = 10 << 24;

# ephemeral ports start here
my $highport_offset = 20_000;

# Create masks to use for services.  the third octet will get filled
# in with a random value.
our $DEFAULT_NTP = ((172 << 24) | (16 << 16) | 53);

our $DEFAULT_DNS = ((172 << 24) | (24 << 16) | 123);

our $DEFAULT_DHCP = ((172 << 24) | (30 << 16) | 67);

# default flow record values
my @DEFAULT_REC_VALUES = (class       => "all",
                          application => 0,
                          init_flags  => make_flags(""),
                          sess_flags  => make_flags(""),
                          attributes  => make_attr(""),
    );

# if true, just print the field names and exit
our $SHOW_FIELDS = 0;

# initialize the random number generator
srand($SRAND_SEED);

# initialize the stime. this will be kept as an offset from the
# $start_date so we don't have to use Math::BigInt to keep track of
# milliseconds
my $stime = rand(3000);

# stop creating flows when the $stime reaches this value
my $MAX_STIME = ($end_date - $start_date) * 1_000;

# how often to write a dot to stderr, in terms of the $stime value
my $dot_timeout = 3_600_000;

# when the next dot timeout occurs
my $next_dot = $dot_timeout;

# the types to use
my @inout = ('in', 'out');

# which printing function to use
my $print_func;

# create hashes to look up values by key
my %name;
@name{@FIELD_KEYS} = @FIELD_NAMES;


# This program's name
our $MYNAME = $0;
$MYNAME =~ s,.*/,,;

END {
    # print final newline
    if ($STATUS_DOTS > 1) {
        print STDERR "\n";
    }

    # force sending of final PDU
    our %pdu;
    if (($pdu{sock} || $pdu{file}) && $pdu{count}) {
        send_pdu();
    }
}


#######################################################################

# variables are initialized.

# parse the user's options
process_options();

# initialize the printing functions
prep_fields();


# if just printing field names, do so and exit
if ($SHOW_FIELDS) {
    print join(",", @name{@FIELDS}), "\n";
    exit 0;
}

# Open output files
if ($IPV4_OUTPUT) {
    our $ipv4_fh;
    if ($IPV4_OUTPUT =~ /^-$/) {
        open $ipv4_fh, ">&STDOUT"
            or die "$MYNAME: Cannot dup stdout: $!\n";
    }
    elsif ($IPV4_OUTPUT =~ /^\|/) {
        open $ipv4_fh, "$IPV4_OUTPUT"
            or die "$MYNAME: Cannot invoke $IPV4_OUTPUT: $!\n";
    }
    else {
        open $ipv4_fh, "> $IPV4_OUTPUT"
            or die "$MYNAME: Cannot open '$IPV4_OUTPUT': $!\n";
    }
}
if ($IPV6_OUTPUT) {
    our $ipv6_fh;
    if ($IPV6_OUTPUT =~ /^-$/) {
        open $ipv6_fh, ">&STDOUT"
            or die "$MYNAME: Cannot dup stdout: $!\n";
    }
    elsif ($IPV6_OUTPUT =~ /^\|/) {
        open $ipv6_fh, "$IPV6_OUTPUT"
            or die "$MYNAME: Cannot invoke $IPV6_OUTPUT: $!\n";
    }
    else {
        open $ipv6_fh, "> $IPV6_OUTPUT"
            or die "$MYNAME: Cannot open '$IPV6_OUTPUT': $!\n";
    }
}
if ($PDU_OUTPUT) {
    our %pdu;
    my $pdu_fh;
    if ($PDU_OUTPUT =~ /^-$/) {
        open $pdu_fh, ">&STDOUT"
            or die "$MYNAME: Cannot dup stdout: $!\n";
    }
    elsif ($PDU_OUTPUT =~ /^\|/) {
        open $pdu_fh, "$PDU_OUTPUT"
            or die "$MYNAME: Cannot invoke $PDU_OUTPUT: $!\n";
    }
    else {
        open $pdu_fh, "> $PDU_OUTPUT"
            or die "$MYNAME: Cannot open '$PDU_OUTPUT': $!\n";
    }
    $pdu{file} = $pdu_fh;
    $pdu{count} = 0;
    $pdu{flow_sequence} = 0;
    $pdu{data} = '';
    $pdu{cur_time} = 0;
}
if ($PDU_HOST_PORT) {
    our %pdu;
    unless ($PDU_HOST_PORT =~ m/^(.+):(\d+)$/) {
        die "$MYNAME: Badly formed host:port pair '$PDU_HOST_PORT'\n";
    }
    my ($host, $port) = ($1, $2);
    if ($host =~ /:/) {
        if ($host !~ m/^\[(.+)\]$/) {
            die "$MYNAME: Must specify IPv6 address as [<ipv6-addr>]:<port>\n";
        }
    }
    $host =~ s/^\[(.+)\]$/$1/;

    $pdu{count} = 0;
    $pdu{flow_sequence} = 0;
    $pdu{data} = '';
    $pdu{cur_time} = 0;

    # attempt to load Perl's IPv6 support unless user explicitly
    # requetsted only IPv4 support
    if (!$PDU_IPV4) {
        # first, see if Socket6 is available, since it is not part of
        # the Perl CORE distribution
        eval "require Socket6";
        if ($@) {
            # Socket6 is not available
            if ($PDU_IPV6) {
                # IPv6 explicitly required.  exit.
                exit 77;
            }
            # If $host is an IPv6 address, exit
            if ($host =~ /:/) {
                exit 77;
            }
            # Force use of IPv4
            $PDU_IPV4 = 1;
        }
        else {
            # Socket6 is available.  Use an eval-string to handle
            # Socket6, so we don't get errors when Socket6 is not
            # available.
            eval << 'EOF';
            use Socket6 ();
            my ($s, $family, $socktype, $proto, $saddr, $canonname, @res);
            @res = Socket6::getaddrinfo($host, $port, AF_UNSPEC, SOCK_DGRAM,
                                        scalar(getprotobyname("udp")));
            if (scalar(@res) == 1) {
                die "$MYNAME: Cannot resolve '$host': @res\n";
            }
            $family = -1;
            while (scalar(@res) >= 5) {
                ($family, $socktype, $proto, $saddr, $canonname, @res) = @res;
                my ($thost, $tport)
                    = Socket6::getnameinfo($saddr,
                                           (Socket6::NI_NUMERICHOST()
                                            | Socket6::NI_NUMERICSERV()));
                #print STDERR "Trying to connect to \[$thost\]:$tport...\n";
                socket($s, $family, $socktype, $proto) || next;
                connect($s, $saddr) && last;
                close($s);
                $family = -1;
            }
            if ($family == -1) {
                die "$MYNAME: Cannot create connection to $PDU_HOST_PORT\n";
            }
            getpeername($s)
                or die ("$MYNAME: Cannot create connection",
                        " to $PDU_HOST_PORT\n");
            $pdu{sock} = $s;
EOF
            die "$@" if $@;
        }
    }

    if ($PDU_IPV4) {
        # Either IPv4 explicitly requested, or IPv6 support is not
        # available in Perl
        my $s;
        my $addr = inet_aton($host)
            or die "$MYNAME: Cannot resolve '$host' to an IPv4 address\n";
        my $sa = sockaddr_in($port, $addr);
        socket($s, AF_INET, SOCK_DGRAM, scalar(getprotobyname("udp")))
            or die "$MYNAME: Cannot create UDP socket: $!\n";
        connect($s, $sa)
            or die "$MYNAME: Cannot create connection to $PDU_HOST_PORT: $!\n";
        getpeername($s)
            or die "$MYNAME: Cannot create connection to $PDU_HOST_PORT\n";
        $pdu{sock} = $s;
    }

    # Send a packet with wrong NetFlow version.  Sometimes an IPv6
    # packet on the Mac gets lost, and I hope this fixes the issue.
    my $noop = pack('n', 7)."\c@" x 22;
    defined(send($pdu{sock}, $noop, 0))
        or die "$MYNAME: Cannot send: $!\n";
}


# print the column headers.  rwtuc uses these to figure out what each
# column contains
print_header();

if ($STATUS_DOTS) {
    $STATUS_DOTS = 2;
    print STDERR "Working";
}

# flows are printed in time-sorted order
my $sorted_flows = [];

while ($stime < $MAX_STIME) {

    if ($STATUS_DOTS && $stime >= $next_dot) {
        print STDERR ".";
        $next_dot += $dot_timeout;
    }

    # flows we add this time
    my $flows = [];

    # generate sensor, IP addresses, ephemeral ports
    my $sensor = 'S'.int(rand(10));
    my $int = $int_offset + int(6553 * log(1+rand(22025)));
    my $ext = $ext_offset + int(1677721 * log(1+rand(22025)));
    my $highport = $highport_offset + int(1000 * log(1+rand(22025)));

    # "choose" the kind of flow record to create
    my $rand = rand 100;

    if ($rand < 25) {
        # traffic coming to our http servers
        http_flows($flows, $stime, $sensor, $ext, $int, $highport, 0);
    }
    elsif ($rand < 50) {
        # traffic to external http servers
        my $dur = dns_flows($flows, $stime, $sensor, $int, undef, $highport);
        $stime += $dur;
        ++$highport;
        http_flows($flows, $stime, $sensor, $int, $ext, $highport, 1);
    }
    elsif ($rand < 60) {
        # traffic to our mail servers
        smtp_flows($flows, $stime, $sensor, $ext, $int, $highport, 0);
    }
    elsif ($rand < 70) {
        # traffic to external mail servers
        my $dur = dns_flows($flows, $stime, $sensor, $int, undef, $highport);
        $stime += $dur;
        ++$highport;
        smtp_flows($flows, $stime, $sensor, $int, $ext, $highport, 1);
    }
    elsif ($rand < 75) {
        # incoming ICMP
        icmp_flows($flows, $stime, $sensor, $ext, $int, 0);
    }
    elsif ($rand < 80) {
        # outgoing ICMP
        icmp_flows($flows, $stime, $sensor, $int, $ext, 1);
    }
    elsif ($rand < 85) {
        # NTP traffic
        ntp_flows($flows, $stime, $sensor, $int, undef, $highport);
    }
    elsif ($rand < 90) {
        # DHCP traffic
        dhcp_flows($flows, $stime, $sensor, $int, undef, $highport);
    }
    elsif ($rand < 95) {
        # traffic to our ssh servers
        ssh_flows($flows, $stime, $sensor, $ext, $int, $highport, 0);
    }
    elsif ($rand < 100) {
        # traffic to external ssh servers
        my $dur = dns_flows($flows, $stime, $sensor, $int, undef, $highport);
        $stime += $dur;
        ++$highport;
        ssh_flows($flows, $stime, $sensor, $int, $ext, $highport, 1);
    }

    # go forward in time.  this value was found through
    # trial-and-error to provide about 500,000 flow records
    $stime += rand($TIMESTEP_MAX);

    # merge sort $flows and $sorted_flows in $new_sorted
    my $new_sorted = [];

    my $f = shift @$flows;
    my $sf = shift @$sorted_flows;
    while (defined($f) && defined($sf)) {
        if ($f->{stime} < $sf->{stime}) {
            if ($f->{stime} < $stime) {
                $print_func->($f);
            } else {
                push @$new_sorted, $f;
            }
            $f = shift @$flows;
        } else {
            if ($sf->{stime} < $stime) {
                $print_func->($sf);
            } else {
                push @$new_sorted, $sf;
            }
            $sf = shift @$sorted_flows;
        }
    }
    if (defined $f) {
        push @$new_sorted, $f, @$flows;
    }
    elsif (defined $sf) {
        push @$new_sorted, $sf, @$sorted_flows;
    }
    $sorted_flows = $new_sorted;
}

# print any remaining flows
while (my $r = shift @$sorted_flows) {
    $print_func->($r);
}

exit;


#######################################################################

# Prepare to print the fields
sub prep_fields
{
    our ($print_format_v4, $print_format_v6);

    my %format;
    @format{@FIELD_KEYS} = @FIELD_FORMATS;

    if ($PDU_HOST_PORT || $PDU_OUTPUT) {
        # use the print_pdu function
        $print_func = \&print_pdu;
    }
    elsif (!@FIELDS && !$COLUMNAR) {
        # use the print_one_rec function
        $print_func = \&print_one_rec;

        @FIELDS = @FIELD_KEYS;

        $print_format_v4 = join "|", @FIELD_FORMATS;
        $print_format_v6 = join "|", @FIELD_FORMATS;
    }
    elsif (!$COLUMNAR) {
        # fields specied
        $print_func = \&print_some_fields;

        $print_format_v4 = join "|", @format{@FIELDS};
        $print_format_v6 = join "|", @format{@FIELDS};
    }
    else {
        # columns and maybe fields specified
        $print_func = \&print_some_fields;

        if (!@FIELDS) {
            @FIELDS = @FIELD_KEYS;
        }

        our ($header_format_v4, $header_format_v6);

        my %width;
        @width{@FIELD_KEYS} = @FIELD_WIDTHS;

        $print_format_v4 = "";
        $print_format_v6 = "";
        $header_format_v4 = "";
        $header_format_v6 = "";

        for my $i (@FIELDS) {
            my $w = $width{$i};
            my $f = $format{$i};
            if ($f =~ /03/) {
                my $s = substr($f, 0, 1) . ($w - 4) . substr($f, 1) . "|";
                $print_format_v4 .= $s;
                $print_format_v6 .= $s;

                $s = sprintf("%%%d.%ds|", $w, $w);
                $header_format_v4 .= $s;
                $header_format_v6 .= $s;
            }
            elsif ($i =~ /^[sd]ip$/) {
                my $s = substr($f, 0, 1) . $w . substr($f, 1) . "|";
                $print_format_v4 .= $s;

                $s = sprintf("%%%d.%ds|", $w, $w);
                $header_format_v4 .= $s;

                $w += $IPV6_ADDED_WIDTH;
                $s = substr($f, 0, 1) . $w . substr($f, 1) . "|";
                $print_format_v6 .= $s;

                $s = sprintf("%%%d.%ds|", $w, $w);
                $header_format_v6 .= $s;
            }
            else {
                my $s = substr($f, 0, 1) . $w . substr($f, 1) . "|";
                $print_format_v4 .= $s;
                $print_format_v6 .= $s;

                $s = sprintf("%%%d.%ds|", $w, $w);
                $header_format_v4 .= $s;
                $header_format_v6 .= $s;
            }
        }
        $header_format_v4 .= "\n";
        $header_format_v6 .= "\n";
    }
    $print_format_v4 .= "\n";
    $print_format_v6 .= "\n";
}


#######################################################################

# Print column headers
sub print_header
{
    our ($ipv4_fh, $ipv6_fh);

    if (!$COLUMNAR) {
        if (defined $ipv4_fh) {
            print $ipv4_fh join "|", @name{@FIELDS};
            print $ipv4_fh "\n";
        }
        if (defined $ipv6_fh) {
            print $ipv6_fh join "|", @name{@FIELDS};
            print $ipv6_fh "\n";
        }
    }
    else {
        our ($header_format_v4, $header_format_v6);

        if (defined $ipv4_fh) {
            printf $ipv4_fh $header_format_v4, @name{@FIELDS};
        }
        if (defined $ipv6_fh) {
            printf $ipv6_fh $header_format_v6, @name{@FIELDS};
        }
    }
    return;
}


#######################################################################

# Take a hashref representing a flow record and print it as text.
# Possible value for $print_func
sub print_one_rec
{
    my ($r) = @_;

    #use Data::Dumper;
    #print Data::Dumper->Dump([$r]);
    #exit;

    our ($print_format_v4, $print_format_v6);
    our ($ipv4_fh, $ipv6_fh);

    if (defined $ipv4_fh) {
        printf($ipv4_fh
               $print_format_v4,
               $r->{sip}, $r->{dip}, $r->{sport}, $r->{dport}, $r->{proto},
               $r->{packets}, $r->{bytes},
               ($start_date + (int($r->{stime})/1000)),(int($r->{stime})%1000),
               (int($r->{dur}) / 1000), (int($r->{dur}) % 1000),
               $r->{sensor}, $r->{class}, $r->{type},
               $r->{input}, $r->{output}, $r->{application},
               $r->{init_flags}, $r->{sess_flags}, $r->{attributes},
            );
    }
    if (defined $ipv6_fh) {
        printf($ipv6_fh
               $print_format_v6,
               sprintf('2001:db8:%x:%x::%x:%x',
                       (0xFF & ($r->{sip} >> 24)), (0xFF & ($r->{sip} >> 16)),
                       (0xFF & ($r->{sip} >>  8)), (0xFF & ($r->{sip}))),
               sprintf('2001:db8:%x:%x::%x:%x',
                       (0xFF & ($r->{dip} >> 24)), (0xFF & ($r->{dip} >> 16)),
                       (0xFF & ($r->{dip} >>  8)), (0xFF & ($r->{dip}))),
               $r->{sport}, $r->{dport},
               (($r->{proto} == 1) ? 58 : $r->{proto}),
               $r->{packets}, $r->{bytes},
               ($start_date + (int($r->{stime})/1000)),(int($r->{stime})%1000),
               (int($r->{dur}) / 1000), (int($r->{dur}) % 1000),
               $r->{sensor}, $r->{class}, $r->{type},
               $r->{input}, $r->{output}, $r->{application},
               $r->{init_flags}, $r->{sess_flags}, $r->{attributes},
            );
    }

    our $MAX_RECORDS;
    if ($MAX_RECORDS > 0) {
        --$MAX_RECORDS;
        if ($MAX_RECORDS == 0) {
            exit;
        }
    }
}


#######################################################################

# Take a hashref representing a flow record and print specified fields
# Possible value for $print_func
sub print_some_fields
{
    my ($r) = @_;

    our ($print_format_v4, $print_format_v6);
    our ($ipv4_fh, $ipv6_fh);

    my @out;

    for my $f (@FIELDS) {
        if ($f eq 'stime') {
            push @out, (($start_date + (int($r->{$f}) / 1000)),
                        (int($r->{$f}) % 1000));
        }
        elsif ($f eq 'dur') {
            push @out, ((int($r->{$f}) / 1000), (int($r->{$f}) % 1000));
        }
        else {
            push @out, $r->{$f};
        }
    }

    if (defined $ipv4_fh) {
        printf $ipv4_fh $print_format_v4, @out;
    }
    if (defined $ipv6_fh) {
        for (my $i = 0; $i < @FIELDS; ++$i) {
            my $f = $FIELDS[$i];
            if ($f =~ /^[sd]ip$/) {
                $out[$i] = sprintf('2001:db8:%x:%x::%x:%x',
                                   (0xFF & ($r->{$f} >> 24)),
                                   (0xFF & ($r->{$f} >> 16)),
                                   (0xFF & ($r->{$f} >>  8)),
                                   (0xFF & ($r->{$f})));
            }
            elsif ($f eq 'proto' && $out[$i] == 1) {
                $out[$i] = 58;
            }
        }

        printf $ipv6_fh $print_format_v6, @out;
    }

    our $MAX_RECORDS;
    if ($MAX_RECORDS > 0) {
        --$MAX_RECORDS;
        if ($MAX_RECORDS == 0) {
            exit;
        }
    }
}


#######################################################################

sub print_pdu
{
    my ($r) = @_;

    my $etime = int($r->{stime}) + int($r->{dur});

    my $flags = 0;
    my $str_flags = $r->{init_flags} . $r->{sess_flags};
    if ($str_flags =~ /F/) { $flags |= 0x01; }
    if ($str_flags =~ /S/) { $flags |= 0x02; }
    if ($str_flags =~ /R/) { $flags |= 0x04; }
    if ($str_flags =~ /P/) { $flags |= 0x08; }
    if ($str_flags =~ /A/) { $flags |= 0x10; }
    if ($str_flags =~ /U/) { $flags |= 0x20; }
    if ($str_flags =~ /E/) { $flags |= 0x40; }
    if ($str_flags =~ /C/) { $flags |= 0x80; }

    our %pdu;

    if ($etime > $pdu{cur_time}) {
        $pdu{cur_time} = $etime;
    }

    $pdu{data} .= pack('NNN'.'nnNN'.'NN'.'nn'.'CCCC'.'nnCCn',
                       $r->{sip}, $r->{dip}, 0,
                       $r->{input}, $r->{output}, $r->{packets}, $r->{bytes},
                       $r->{stime}, $etime,
                       $r->{sport}, $r->{dport},
                       0, $flags, $r->{proto}, 0,
                       0, 0, 0, 0, 0);
    ++$pdu{count};

    if ($pdu{count} == 30) {
        send_pdu();
    }

    our $MAX_RECORDS;
    if ($MAX_RECORDS > 0) {
        --$MAX_RECORDS;
        if ($MAX_RECORDS == 0) {
            if ($pdu{count}) {
                send_pdu();
            }
            exit;
        }
    }
}


#######################################################################

sub send_pdu
{
    our %pdu;

    my $header = pack('nnNNNNCCn',
                      # Version
                      5,
                      # Count of flows in this packet
                      $pdu{count},
                      # Router Uptime, in milliseconds
                      $pdu{cur_time},
                      # Current time, in epoch seconds
                      ($start_date + (int($pdu{cur_time} / 1000))),
                      # Nanosecond resolution of current time
                      (($pdu{cur_time} % 1000) * 1_000_000),
                      # Number of records sent in previous packets
                      $pdu{flow_sequence},
                      # Engine Type / Engine Id / Sampling Interval
                      1, 2, 0);

    if ($pdu{sock}) {
        defined(send($pdu{sock}, ($header . $pdu{data}), 0))
            or die "$MYNAME: Cannot send: $!\n";
    }
    if ($pdu{file}) {
        my $pdu_fh = $pdu{file};
        if ($pdu{count} < 30) {
            $pdu{data} .= "\c@" x (48 * (30 - $pdu{count}));
        }
        print $pdu_fh $header.$pdu{data};
    }

    $pdu{flow_sequence} += $pdu{count};
    $pdu{count} = 0;
    $pdu{data} = '';
    $pdu{cur_time} = 0;

    return;
}


#######################################################################

sub process_options
{
    # local vars
    my ($help, @user_fields);
    my ($pdu_4net, $pdu_6net, $pdu_anynet);

    GetOptions('help|h|?'       => \$help,
               'status'         => \$STATUS_DOTS,
               'columnar'       => \$COLUMNAR,
               'fields=s'       => \@user_fields,
               'show-fields'    => \$SHOW_FIELDS,
               'max-records=i'  => \$MAX_RECORDS,
               'ipv4-output=s'  => \$IPV4_OUTPUT,
               'ipv6-output=s'  => \$IPV6_OUTPUT,
               'pdu-output=s'   => \$PDU_OUTPUT,
               'pdu-network=s'  => \$pdu_anynet,
               'pdu-4network=s'  => \$pdu_4net,
               'pdu-6network=s'  => \$pdu_6net,
        )
        or usage(1);

    # help?
    if ($help) {
        usage(0);
    }

    if (@user_fields) {
        @user_fields = split(/,/, join(',', @user_fields));

        my %name_to_key;
        @name_to_key{map {"\L$_"} @FIELD_NAMES} = @FIELD_KEYS;

        for my $f (@user_fields) {
            unless ($name_to_key{"\L$f"}) {
                die "$MYNAME: Unknown field value '$f'\n";
            }
            push @FIELDS, $name_to_key{"\L$f"};
        }
    }

    # figure out how to send PDUs over network
    if ($pdu_anynet) {
        $PDU_HOST_PORT = $pdu_anynet;
    }
    if ($pdu_4net) {
        if ($PDU_HOST_PORT) {
            die "$MYNAME: May only specify one of --pdu-*network\n";
        }
        $PDU_HOST_PORT = $pdu_4net;
        $PDU_IPV4 = 1;
    }
    if ($pdu_6net) {
        if ($PDU_HOST_PORT) {
            die "$MYNAME: May only specify one of --pdu-*network\n";
        }
        $PDU_HOST_PORT = $pdu_6net;
        $PDU_IPV6 = 1;
    }

    unless ($SHOW_FIELDS || $IPV4_OUTPUT || $IPV6_OUTPUT || $PDU_OUTPUT
            || $PDU_HOST_PORT)
    {
        die ("$MYNAME: One of --show-fields, --ipv4-output, --ipv6-output,",
             "--pdu-output, --pdu-{,4,6}network is required\n");
    }
    if (($IPV4_OUTPUT || $IPV6_OUTPUT) && ($PDU_HOST_PORT || $PDU_OUTPUT)) {
        die ("$MYNAME: Cannot mix the --pdu-* switches",
             " with the --ipv* switches\n");
    }
}


#######################################################################

# Create flags in the same way as rwcut
sub make_flags
{
    my ($flags) = @_;

    my $out_flags = "        ";
    if ($flags =~ /F/) { $out_flags =~ s/^./F/; }
    if ($flags =~ /S/) { $out_flags =~ s/^(.)./$1S/; }
    if ($flags =~ /R/) { $out_flags =~ s/^(..)./$1R/; }
    if ($flags =~ /P/) { $out_flags =~ s/^(...)./$1P/; }
    if ($flags =~ /A/) { $out_flags =~ s/^(....)./$1A/; }
    if ($flags =~ /U/) { $out_flags =~ s/^(.....)./$1U/; }
    if ($flags =~ /E/) { $out_flags =~ s/^(......)./$1E/; }
    if ($flags =~ /C/) { $out_flags =~ s/^(.......)./$1C/; }
    return $out_flags;
}


#######################################################################

# Create attributes in the same way as rwcut
sub make_attr
{
    my ($attr) = @_;

    my $out_attr = "        ";
    if ($attr =~ /T/) { $out_attr =~ s/^./T/; }
    if ($attr =~ /C/) { $out_attr =~ s/^(.)./$1C/; }
    return $out_attr;
}


#######################################################################

# Create a DNS flow and response
sub dns_flows
{
    my ($flows, $stime, $sensor, $sip, $dip, $highport) = @_;

    if (!defined $dip) {
        our $DEFAULT_DNS;
        $dip = ($DEFAULT_DNS | (int(1 + rand 3) << 8));
    }

    my $outbytes = 54 + rand(15);
    my $inbytes = 132 + rand(200);
    my $outdur = 1 + rand(200_000) / 1_000;

    # don't exceed the maximum time
    if ($outdur + $stime > $MAX_STIME) {
        $outdur = $MAX_STIME - $stime;
    }

    push @$flows, (
        {@DEFAULT_REC_VALUES,
         sip => $sip, dip => $dip, sport => $highport, dport => 53,
         proto => 17, packets => 1, bytes => $outbytes,
         stime => $stime, dur => $outdur,
         sensor => $sensor, type => 'out',
         input => ($sip >> 24), output => ($dip >> 24), application => 53},
        {@DEFAULT_REC_VALUES,
         sip => $dip, dip => $sip, sport => 53, dport => $highport,
         proto => 17, packets => 1, bytes => $inbytes,
         stime => $stime + $outdur, dur => 0,
         sensor => $sensor, type => 'in',
         input => ($dip >> 24), output => ($sip >> 24), application => 53},
    );
    return $outdur;
}


#######################################################################

# Create a DHCP flow and response
sub dhcp_flows
{
    my ($flows, $stime, $sensor, $sip, $dip) = @_;

    if (!defined $dip) {
        our $DEFAULT_DHCP;
        $dip = ($DEFAULT_DHCP | (int(1 + rand 3) << 8));
    }

    my $outdur = 6 + rand(40);

    # don't exceed the maximum time
    if ($outdur + $stime > $MAX_STIME) {
        $outdur = $MAX_STIME - $stime;
    }

    push @$flows, (
        {@DEFAULT_REC_VALUES,
         sip => $sip, dip => $dip, sport => 68, dport => 67,
         proto => 17, packets => 1, bytes => 328,
         stime => $stime, dur => $outdur,
         sensor => $sensor, type => 'out',
         input => ($sip >> 24), output => ($dip >> 24), application => 67},
        {@DEFAULT_REC_VALUES,
         sip => $dip, dip => $sip, sport => 67, dport => 68,
         proto => 17, packets => 1, bytes => 328,
         stime => $stime + $outdur, dur => 0,
         sensor => $sensor, type => 'in',
         input => ($dip >> 24), output => ($sip >> 24), application => 67},
    );
}


#######################################################################

# Create an ICMP flow record
sub icmp_flows
{
    my ($flows, $stime, $sensor, $sip, $dip, $direction) = @_;

    my $rand = rand 10;
    my ($t, $c, $bytes);
    if ($rand < 5) {
        # echo reply; 84 bytes
        $t = 0; $c = 0;
        $bytes = 84;
    }
    elsif ($rand < 7) {
        # timeout
        $t = 11; $c = 0;
        $bytes = 56;
    }
    elsif ($rand < 8) {
        # echo; 84 bytes
        $t = 8; $c = 0;
        $bytes = 84;
    }
    elsif ($rand < 9) {
        # host unreachable
        $t = 3; $c = 1;
        $bytes = 56;
    }
    elsif ($rand < 10) {
        # port unreachable
        $t = 3; $c = 3;
        $bytes = 56;
    }

    # multiple ICMP packets can become a single flow
    my $packets = 1 + int(log(1+rand(22026)));
    $bytes *= $packets;

    push @$flows, (
        {@DEFAULT_REC_VALUES,
         sip => $sip, dip => $dip, sport => 0, dport => (($t << 8) | $c),
         proto => 1, packets => $packets, bytes => $bytes,
         stime => $stime, dur => 0,
         sensor => $sensor, type => $inout[$direction],
         input => ($sip >> 24), output => ($dip >> 24)},
    );
}


#######################################################################

# Create an NTP flow and response
sub ntp_flows
{
    my ($flows, $stime, $sensor, $sip, $dip) = @_;

    if (!defined $dip) {
        our $DEFAULT_NTP;
        $dip = ($DEFAULT_NTP | (int(1 + rand 3) << 8));
    }

    my $outdur = 51 + rand(40);

    # don't exceed the maximum time
    if ($outdur + $stime > $MAX_STIME) {
        $outdur = $MAX_STIME - $stime;
    }

    push @$flows, (
        {@DEFAULT_REC_VALUES,
         sip => $sip, dip => $dip, sport => 123, dport => 123,
         proto => 17, packets => 1, bytes => 76,
         stime => $stime, dur => $outdur,
         sensor => $sensor, type => 'out',
         input => ($sip >> 24), output => ($dip >> 24), application => 123},
        {@DEFAULT_REC_VALUES,
         sip => $dip, dip => $sip, sport => 123, dport => 123,
         proto => 17, packets => 1, bytes => 76,
         stime => $stime + $outdur, dur => 0,
         sensor => $sensor, type => 'in',
         input => ($dip >> 24), output => ($sip >> 24), application => 123},
    );
}


#######################################################################

# Create email flows coming from client to server
sub smtp_flows
{
    my ($flows, $stime, $sensor, $client_ip, $server_ip,
        $client_port, $direction) = @_;

    # max value to subtract from client duration to get server duration
    my $min_client_duration = 300;

    my $client_packets = 10 + rand(40);
    my $client_bytes = 600 + rand(1000) + 1200 * ($client_packets - 10);
    my $client_dur = 1023 + rand(3000);

    # don't exceed the maximum time
    if ($stime + $client_dur > $MAX_STIME) {
        $client_dur = $MAX_STIME - $stime;
        if ($client_dur < $min_client_duration) {
            return;
        }
    }

    my $server_port = 25;
    my $server_packets = $client_packets - 2;
    my $server_bytes = 500 + rand(500) + 61 * ($server_packets - 8);
    my $server_dur = $client_dur - 100 - rand(200);

    # set server stime so flows finish at the same time
    my $server_stime = $stime + $client_dur - $server_dur;

    push @$flows, (
        # the client flow
        {@DEFAULT_REC_VALUES,
         sip => $client_ip, dip => $server_ip,
         sport => $client_port, dport => $server_port, proto => 6,
         packets => $client_packets, bytes => $client_bytes,
         stime => $stime, dur => $client_dur,
         sensor => $sensor, type => $inout[$direction],
         input => ($client_ip >> 24), output => ($server_ip >> 24),
         application => 25,
         init_flags => make_flags('S'), sess_flags => make_flags('FSPA')},
        # the server flow
        {@DEFAULT_REC_VALUES,
         sip => $server_ip, dip => $client_ip,
         sport => $server_port, dport => $client_port, proto => 6,
         packets => $server_packets, bytes => $server_bytes,
         stime => $server_stime, dur => $server_dur,
         sensor => $sensor, type => $inout[!$direction],
         input => ($server_ip >> 24), output => ($client_ip >> 24),
         application => 25,
         init_flags => make_flags('SA'), sess_flags => make_flags('FPA')},
    );
}


#######################################################################

# Create ssh session flows between client and server
sub ssh_flows
{
    my ($flows, $stime, $sensor, $client_ip, $server_ip,
        $client_port, $direction) = @_;

    # base everything off the time of the session: duration is
    # 5mintues + up to 3 hours
    my $total_dur = 300_000 + rand(10_800_000);

    # never allow a duration less that this value
    my $min_client_dur = 1_000;

    # don't exceed the maximum time
    if ($stime + $total_dur > $MAX_STIME) {
        $total_dur = $MAX_STIME - $stime;
        if ($total_dur < $min_client_dur) {
            return;
        }
    }

    my $server_port = 22;

    my $init_flags = make_flags('S');
    my $sess_flags = make_flags('PA');

    # flow timeout is 30 minutes
    my $timeout = 1_800_000;

    while ($total_dur > 0) {
        my $client_dur;
        if ($total_dur < $timeout) {
            $client_dur = $total_dur;
        } else {
            $client_dur = $timeout - $min_client_dur - rand(30_000);
        }
        $total_dur -= $client_dur;

        my $client_packets = 30 + rand(1000) + $client_dur / 5000;
        my $client_bytes = 600 + rand(1000) + 72 * ($client_packets - 10);

        my $server_packets = $client_packets - 2;
        my $server_bytes = 505 + rand(10_000) + 1200 * $server_packets;
        my $server_dur;

        my $attr = make_attr('');

        if ($init_flags =~ /S/) {
            # this is the first flow
            $server_dur = $client_dur - 100 - rand(500);
        } else {
            # this is a continuation flow
            $attr = make_attr($attr . 'C');
            $server_dur = $client_dur - rand(3);
        }

        if ($total_dur == 0) {
            # this will be the final flow
            $sess_flags = make_flags($sess_flags.'F');
        }
        else {
            # the flow will continue
            $attr = make_attr($attr . 'T');
        }

        # set server stime so flows finish at the same time
        my $server_stime = $stime + $client_dur - $server_dur;

        push (@$flows,
              # the client flow
              {@DEFAULT_REC_VALUES,
               sip => $client_ip, dip => $server_ip,
               sport => $client_port, dport => $server_port, proto => 6,
               packets => $client_packets, bytes => $client_bytes,
               stime => $stime, dur => $client_dur,
               sensor => $sensor, type => $inout[$direction],
               input => ($client_ip >> 24), output => ($server_ip >> 24),
               application => 22, init_flags => $init_flags,
               sess_flags => $sess_flags, attributes => $attr},
              # the server flow
              {@DEFAULT_REC_VALUES,
               sip => $server_ip, dip => $client_ip,
               sport => $server_port, dport => $client_port, proto => 6,
               packets => $server_packets, bytes => $server_bytes,
               stime => $server_stime, dur => $server_dur,
               sensor => $sensor, type => $inout[!$direction],
               input => ($server_ip >> 24), output => ($client_ip >> 24),
               application => 22, init_flags => (($init_flags =~ /S/)
                                                 ? make_flags('SA')
                                                 : $init_flags),
               sess_flags => $sess_flags, attributes => $attr},
            );

        $init_flags = $sess_flags;
        $stime += $client_dur;
    }
}


#######################################################################

# Create http,https flows between client and server
sub http_flows
{
    my ($flows, $stime, $sensor, $client_ip, $server_ip,
        $client_port, $direction) = @_;

    # max value to subtract from client duration to get server duration
    my $min_client_duration = 220;

    my $client_packets = 8 + rand(600);
    my $client_bytes = 100 + (60 + rand(40)) * $client_packets;
    my $client_dur = 300 + rand(30_000);

    # don't exceed the maximum time
    if ($stime + $client_dur > $MAX_STIME) {
        $client_dur = $MAX_STIME - $stime;
        if ($client_dur < $min_client_duration) {
            return;
        }
    }

    my $rand = int(rand(20));
    my $server_port = (($rand < 2)
                       ? 8080
                       : (($rand < 6)
                          ? 443
                          : 80));
    my $server_packets = $client_packets + 5 - rand(10);
    my $server_bytes = 1000 + (400 + rand(4000)) * $server_packets;
    my $server_dur = $client_dur - 20 - rand(200);

    # set server stime so flows finish at the same time
    my $server_stime = $stime + $client_dur - $server_dur;

    push @$flows, (
        # the client flow
        {@DEFAULT_REC_VALUES,
         sip => $client_ip, dip => $server_ip,
         sport => $client_port, dport => $server_port, proto => 6,
         packets => $client_packets, bytes => $client_bytes,
         stime => $stime, dur => $client_dur,
         sensor => $sensor, type => $inout[$direction] . 'web',
         input => ($client_ip >> 24), output => ($server_ip >> 24),
         application => ((443 == $server_port) ? 443 : 80),
         init_flags => make_flags('S'),
         sess_flags => make_flags('FPA'.((($rand % 6) == 0) ? 'R' : ''))},
        # the server flow
        {@DEFAULT_REC_VALUES,
         sip => $server_ip, dip => $client_ip,
         sport => $server_port, dport => $client_port, proto => 6,
         packets => $server_packets, bytes => $server_bytes,
         stime => $server_stime, dur => $server_dur,
         sensor => $sensor, type => $inout[!$direction] . 'web',
         input => ($server_ip >> 24), output => ($client_ip >> 24),
         application => ((443 == $server_port) ? 443 : 80),
         init_flags => make_flags('SA'),
         sess_flags => make_flags('FPA'.((($rand % 7) == 0) ? 'R' : ''))},
    );
}


sub usage
{
    my ($exit_val) = @_;

    my $usage = <<'EOF';
make-data.pl [--status] [--columnar] [--fields=FIELDS] [--show-fields]
     {--ipv4-output=PATH_OR_CMD
      | --ipv6-output=PATH_OR_CMD
      | --pdu-output=PATH_OR_CMD
      | --pdu-network=HOST:PORT
      | --pdu-4network=HOST:PORT
      | --pdu-6network=HOST:PORT}


Create output to use for testing the SiLK tool suite.  make-data.pl
can create textual output that can be piped to rwtuc to create a SiLK
Flow file, or it can create NetFlow v5 PDUs for testing the SiLK
packing system.

At least one of --ipv4-output, --ipv6-output, --pdu-output, or
--pdu-{,4,6}network must be specified.  The --pdu-output and
--pdu-{,4,6}network switches cannot be mixed with the --ipv4-output
and --ipv6-output switches.  However, both --pdu-output and
--pdu-{,4,6}network may be specified in a single invocation, and both
--ipv4-output and --ipv6-output may be specified in a single
invocation.

The --pdu-{,4,6}network switches expect a "host:port" pair where the
data will be sent.  The host may be enclosed in square brackets, and
must be so enclosed when "host" is an IPv6 address.  The
--pdu-4network switch forces the connection to occur using the IPv4
address of "host".  The --pdu-6network switch forces the connection to
occur using the IPv6 address of "host".  The --pdu-network switch
resolves "host", and uses the IPv6 address if one exists, else it uses
the IPv4 address.  IPv6 connections require the Socket6 module; if
this module is not available and --pdu-6network is specified, the
program exits with status 77.

If the argument to --ipv4-output, --ipv6-output, or --pdu-output
switch begins with a pipe ('|'), the textual data is piped into the
named command.  If the argument is a single hyphen ('-'), the text is
written to the standard output.  Otherwise, the argument to the switch
is taken to be the path to the text file to create.

Options:
    --help
        Print this message and exit.
    --status
        Print dots to stderr while generating data.
    --columnar
        Print output in columns.  Normally text is printed as
        pipe-delimited text with no spaces.
    --fields=FIELDS
        Print the named fields in the specified order.
    --show-fields
        Print the field names as a comma separated list and exit.
    --max-records
        Print this many records, 0==unlimited
    --ipv4-output=PATH_OR_CMD
        Pipe IPv4 text to given command or print IPv4 records to the
        named location.
    --ipv6-output=PATH_OR_CMD
        Pipe IPv6 text to given command or print IPv6 records to the
        named location.
    --pdu-output=PATH_OR_CMD
        Create NetFlow v5 PDUs and write them as a stream to the named
        location.
    --pdu-network=HOST:PORT
        Create NetFlow v5 PDUs and send them to the host:port pair
        that is specified.  Uses the IPv6 of "host" if available;
        otherwise uses the IPv4 address.
    --pdu-4network=HOST:PORT
        Like --pdu-network, but only uses the IPv4 address of "host".
    --pdu-6network=HOST:PORT
        Like --pdu-network, but only uses the IPv6 address of "host".
        The script will exit with status 77 if the Socket6 module is
        not available.
EOF

    if ($exit_val) {
        print STDERR $usage;
    }
    else {
        print $usage;
    }

    exit $exit_val;
}

__END__
