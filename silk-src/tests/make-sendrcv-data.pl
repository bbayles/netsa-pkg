#! /usr/bin/perl -w
#

#######################################################################
## Copyright (C) 2010-2023 by Carnegie Mellon University.
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
#  make-sendrcv-data.pl
#
#    This script generates files to be used to test the connection
#    between rwsender and rwreceiver.
#
#    The variable '@OUTPUT_FILES' contains the files to create.
#
#  Mark Thomas
#  March 2010
#######################################################################
#  RCSIDENT("$SiLK: make-sendrcv-data.pl b2b562f1ea39 2023-02-20 17:50:25Z mthomas $")
#######################################################################

use strict;
use Fcntl qw(:DEFAULT :seek);
use Getopt::Long qw(GetOptions);


# The list of files to create.  Each file is composed of a triple,
# containing the file-name, file-size, and srand-seed to use when
# generating the file.  By specifying an srand-seed for each file,
# changing the size of one file does not change the contents of the
# other files.  If srand-seed is 0, each byte of the file is set to
# 0x55.

our @OUTPUT_FILES = (
    # (FILE_NAME, FILE_SIZE, SEED),
    ("random-bytes.a", 580389, 80723),
    ("random-bytes.b", 588682, 29719),
    ("random-bytes.c", 558792, 38775),
    ("random-bytes.d", 506536, 64358),
    ("random-bytes.e", 565627, 63126),
    ("random-bytes.f", 531333, 37039),
    ("random-bytes.g", 554365, 17099),
    ("random-bytes.h", 505356, 53600),
    ("random-bytes.i", 587897, 24227),
    ("random-bytes.j", 568476, 89438),
    );

# what to do
our $PRINT_NAMES = 0;
our $PRINT_INFO = 0;
our $MAKE_FILES = 0;
our $MD5_OUT;

# parse the user's options
process_options();

if ($PRINT_NAMES) {
    print_names();
}
if ($PRINT_INFO) {
    print_info();
}
if ($MAKE_FILES) {
    make_files();
}

exit;


#######################################################################

sub make_files
{
    if ($MD5_OUT) {
        eval { require Digest::MD5; Digest::MD5->import; };
        if ($@) {
            warn "Warning: Digest::MD5 not available\n";
            undef $MD5_OUT;
        }
    }

    while (my ($file, $size, $seed) = splice @OUTPUT_FILES, 0, 3)
    {
        my $orig_size = $size;

        sysopen F, $file, O_RDWR|O_CREAT|O_TRUNC
            or die "Cannot open '$file' for writing: $!\n";
        binmode F;

        if (0 == $seed) {
            my $count = 1024;
            my $buf = pack "N$count", ((0x55555555) x $count);
            my $bufsize = 4 * $count;

            while ($size > 0) {
                # when $size > sizeof($buf), only sizeof($buf) characters
                # are written
                my $written = syswrite F, $buf, $size;
                if (!defined $written) {
                    die "Error writing to '$file': $!\n";
                }
                $size -= $written;
            }
        }
        else {
            srand($seed);
            my $count = 1024;
            my $bufsize = 4 * $count;

            while ($size > 0) {
                if ($bufsize > $size) {
                    # can create fewer random numbers
                    $count = (($size - 1) >> 2) + 1;
                    $bufsize = $size;
                }

                my $buf = "";
                for (my $i = 0; $i < $count; ++$i) {
                    $buf .= pack "N", int(rand(0xFFFFFFFF));
                }

                my $offset = 0;
                while ($offset < $bufsize) {
                    # when $size > sizeof($buf), only sizeof($buf)
                    # characters are written
                    my $written = syswrite F, $buf, $size, $offset;
                    if (!defined $written) {
                        die "Error writing to '$file': $!\n";
                    }
                    $size -= $written;
                    $offset += $written;
                }
            }
        }

        if ($MD5_OUT) {
            our $OUTPUT;

            sysseek F, 0, SEEK_SET
                or die "Cannot seek in '$file': $!";

            my $digest = Digest::MD5->new;
            $digest->addfile(*F);
            my $md5 = $digest->hexdigest;
            $OUTPUT .= "$file $orig_size $md5\n";
        }

        close F
            or die "Cannot close '$file': $!\n";
    }

    if ($MD5_OUT) {
        our $OUTPUT;
        if ($MD5_OUT eq '-') {
            print $OUTPUT;
        }
        else {
            open F, ">", $MD5_OUT
                or die "Cannot open '$MD5_OUT' for writing: $!\n";
            print F $OUTPUT;
            close F
                or die "Cannot close '$MD5_OUT': $!\n";
        }
    }
}


#######################################################################

sub print_names
{
    my @file_list;

    for (my $i = 0; $i < @OUTPUT_FILES; $i += 3) {
        push @file_list, $OUTPUT_FILES[$i];
    }
    if (@file_list) {
        print join(" ", @file_list), "\n";
    }
}


#######################################################################

sub print_info
{
    my @out_files = @OUTPUT_FILES;

    my $max_len = 0;
    for (my $i = 0; $i < @out_files; $i += 3) {
        my $len = length $out_files[$i];
        if ($len > $max_len) {
            $max_len = $len;
        }
    }

    while (my ($file, $size, $seed) = splice @out_files, 0, 3)
    {
        printf("%${max_len}s%12u%12u\n", $file, $size, $seed);
    }
}

#######################################################################

sub process_options
{
    # local vars
    my ($help);

    # import globals
    our ($PRINT_NAMES, $PRINT_INFO, $MAKE_FILES, $MD5_OUT);

    GetOptions('help|h|?'       => \$help,
               'print-names'    => \$PRINT_NAMES,
               'print-info'     => \$PRINT_INFO,
               'make-files'     => \$MAKE_FILES,
               'md5-out=s'      => \$MD5_OUT,
        )
        or usage(1);

    # help?
    if ($help) {
        usage(0);
    }
    # must specify something to do
    if (!$MAKE_FILES && !$PRINT_NAMES && !$PRINT_INFO) {
        usage(1);
    }
}


#######################################################################

sub usage
{
    my ($exit_val) = @_;

    my $usage = <<'EOF';
make-sendrcv-data.pl {--print-names|--print-info|--make-files [--md5-out=FILE]}

Create files for testing rwsender/rwreceiver.

Options:
    --help          Print this message and exit.
    --print-names   Print names of files that will be created to stdout
    --print-info    Print information about files to be created to stdout
    --make-files    Generate the output files
    --md5-out=FILE  Print to 'FILE' a line for each file created, where each
                    line contains "<filename> <filesize> <md5>"
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
