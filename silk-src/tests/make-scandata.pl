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
#  make-scandata.pl
#
#    This script generates textual output that can be feed to rwtuc to
#    create flow records that simulate scanning.  This script only
#    creates flows for scans.  The output should be merged with the
#    normal flow traffic.
#
#    Data orginates from 10.0.0.0/8 and targets 192.168.0.0/16.
#
#    Data covers a 3 day period:
#    Feb 12 00:00:00 2009 --- Feb 14 23:59:59 2009 UTC
#
#  Mark Thomas
#  March 2009
#######################################################################
#  RCSIDENT("$SiLK: make-scandata.pl b2b562f1ea39 2023-02-20 17:50:25Z mthomas $")
#######################################################################


use Getopt::Long qw(GetOptions);

our $STATUS_DOTS = 0;
our $COLUMNAR = 0;
our @FIELDS = ();
our $MAX_RECORDS = 0;

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
our @FIELD_FORMATS = qw(%u %u %u %u %u
                        %u %u %u.%03d %d.%03d
                        %s %s %s %u %u %u
                        %s %s %s);

# Seed used to initialize the pseudo-random number generator
my $SRAND_SEED = 18272728;

# Maximum time step to use
my $TIMESTEP_MAX = 2000;

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

# default flow record values
my @DEFAULT_REC_VALUES = (class       => "all",
                          application => 0,
                          init_flags  => make_flags(0),
                          sess_flags  => make_flags(0),
                          attributes  => "",
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
my $max_stime = ($end_date - $start_date) * 1_000;

# how often to write a dot to stderr, in terms of the $stime value
my $dot_timeout = 3_600_000;

# when the next dot timeout occurs
my $next_dot = $dot_timeout;

# the types to use
my @inout = ('in');

# which printing function to use
my $print_func;

# create hashes to look up values by key
my %name;
@name{@FIELD_KEYS} = @FIELD_NAMES;

my %width;
@width{@FIELD_KEYS} = @FIELD_WIDTHS;

my %format;
@format{@FIELD_KEYS} = @FIELD_FORMATS;


END {
    # print final newline
    if ($STATUS_DOTS > 1) {
        print STDERR "\n";
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

# print the column headers.  rwtuc uses these to figure out what each
# column contains
print_header();

if ($STATUS_DOTS) {
    $STATUS_DOTS = 2;
    print STDERR "Working";
}

my $udp_scan = {
    sip    => 0,
    dip    => 0,
    sport  => 0,
    dport  => 0,
    type   => 'in',
    count  => [],
};

my $tcp_scan = {
    sip    => 0,
    dip    => 0,
    sport  => 0,
    dport  => 0,
    type   => 'in',
    count  => [],
};


# outside while() to maintain state
my $scan;

while ($stime < $max_stime) {

    if ($STATUS_DOTS && $stime >= $next_dot) {
        print STDERR ".";
        $next_dot += $dot_timeout;
    }

    my $proto;
    my $flags = "";
    my $bytes = 25 + int(rand(10));

    if (rand(3) < 2) {
        # TCP scan packet
        $proto = 6;
        $bytes = 40;
        # set flags to either S or SA
        $flags = make_flags(0x02 | ((rand(2) > 1) ? 0x10 : 0));

        $scan = $tcp_scan;
        unless (@{$scan->{count}}) {
            my $o3 = int(rand 256) << 8;
            for my $i (0..255) {
                $scan->{count}[$i] = ($o3 | $i);
            }
            $scan->{sip} = (10 << 24) + int(rand(1 << 24));
            $scan->{sport} = 9999 + int(rand(55000));
            $scan->{dport} = (80, 443, 25, 22)[rand(4)];
            if ($scan->{dport} == 80 || $scan->{dport} == 443) {
                $scan->{type} = 'inweb';
            } else {
                $scan->{type} = 'in';
            }
        }
        $scan->{dip} = (192 << 24) | (168 << 16) | shift @{$scan->{count}};
    }
    else {
        # UDP scan packet
        $proto = 17;
        $scan = $udp_scan;
        unless (@{$scan->{count}}) {
            my @ports = (1..1023);
            while (@ports) {
                push @{$scan->{count}}, (splice @ports, int(rand(@ports)), 1);
            }

            $scan->{sip} = (10 << 24) | int(rand(1 << 24));
            $scan->{dip} = (192 << 24) | (168 << 16) | int(rand(1 << 16));
            $scan->{sport} = 10000 + int(rand(55536));
        }
        $scan->{dport} = shift @{$scan->{count}};
    }

    $print_func->({@DEFAULT_REC_VALUES,
                   sip => $scan->{sip}, dip => $scan->{dip},
                   sport => $scan->{sport}, dport => $scan->{dport},
                   proto => $proto,
                   packets => 1, bytes => $bytes,
                   stime => $stime, dur => 0,
                   sensor => 'S'.int(rand(10)), type => $scan->{type},
                   input => 10, output => 192,
                   init_flags => $flags,
                  });

    $stime += rand($TIMESTEP_MAX);
}

exit;


#######################################################################

# Prepare to print the fields
sub prep_fields
{
    our $print_format;

    if (!@FIELDS && !$COLUMNAR) {
        # use the print_one_rec function
        $print_func = \&print_one_rec;

        @FIELDS = @FIELD_KEYS;

        $print_format = join "|", @FIELD_FORMATS;
    }
    elsif (!$COLUMNAR) {
        # fields specied
        $print_func = \&print_some_fields;

        $print_format = join "|", @format{@FIELDS};
    }
    else {
        # columns and maybe fields specified
        $print_func = \&print_some_fields;

        if (!@FIELDS) {
            @FIELDS = @FIELD_KEYS;
        }

        $print_format = "";
        for my $i (@FIELDS) {
            my $w = $width{$i};
            my $f = $format{$i};
            if ($f =~ /03/) {
                $print_format .= substr($f, 0, 1).($w - 4).substr($f, 1)."|";
            }
            else {
                $print_format .= substr($f, 0, 1) . $w . substr($f, 1) . "|";
            }
        }
    }
    $print_format .= "\n";
}


#######################################################################

# Print column headers
sub print_header
{
    if (!$COLUMNAR) {
        print join "|", @name{@FIELDS};
    }
    else {
        my $format = join ("", (map {sprintf("%%%d.%ds|", $_, $_)}
                                @width{@FIELDS}));
        printf $format, @name{@FIELDS};
    }
    print "\n";
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

    printf($print_format,
           $r->{sip}, $r->{dip}, $r->{sport}, $r->{dport}, $r->{proto},
           $r->{packets}, $r->{bytes},
           ($start_date + (int($r->{stime}) / 1000)),(int($r->{stime}) % 1000),
           (int($r->{dur}) / 1000), (int($r->{dur}) % 1000),
           $r->{sensor}, $r->{class}, $r->{type},
           $r->{input}, $r->{output}, $r->{application},
           $r->{init_flags}, $r->{sess_flags}, $r->{attributes},
        );

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

    printf $print_format, @out;

    our $MAX_RECORDS;
    if ($MAX_RECORDS > 0) {
        --$MAX_RECORDS;
        if ($MAX_RECORDS == 0) {
            exit;
        }
    }
}


#######################################################################

sub process_options
{
    # local vars
    my ($help, @user_fields);

    GetOptions('help|h|?'       => \$help,
               'status'         => \$STATUS_DOTS,
               'columnar'       => \$COLUMNAR,
               'fields=s'       => \@user_fields,
               'show-fields'    => \$SHOW_FIELDS,
               'max-records=i'  => \$MAX_RECORDS,
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
                die "Unknown field value '$f'\n";
            }
            push @FIELDS, $name_to_key{"\L$f"};
        }
    }
}


#######################################################################

# Create flags in the same way as rwcut
sub make_flags
{
    my ($flags) = @_;

    my $out_flags = "        ";
    if ($flags & 0x01) { $out_flags =~ s/^./F/; }
    if ($flags & 0x02) { $out_flags =~ s/^(.)./$1S/; }
    if ($flags & 0x04) { $out_flags =~ s/^(..)./$1R/; }
    if ($flags & 0x08) { $out_flags =~ s/^(...)./$1P/; }
    if ($flags & 0x10) { $out_flags =~ s/^(....)./$1A/; }
    if ($flags & 0x20) { $out_flags =~ s/^(.....)./$1U/; }
    if ($flags & 0x40) { $out_flags =~ s/^(......)./$1E/; }
    if ($flags & 0x80) { $out_flags =~ s/^(.......)./$1C/; }
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


sub usage
{
    my ($exit_val) = @_;

    my $usage = <<'EOF';
make-scandata.pl [--status] [--columnar] [--fields=FIELDS] [--show-fields]

Create textual output to use for testing the SiLK tool suite.  The output
from make-scandata.pl can be piped to rwtuc to create a SiLK Flow file.

Options:
    --help          Print this message and exit.
    --status        Print dots to stderr while generating data
    --columnar      Print output in columns
    --fields=FIELDS Only print the named fields
    --show-fields   Print the field names as a comma separated list and exit
    --max-records   Print only this many records, 0==unlimited
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
