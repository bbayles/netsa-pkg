#! /usr/bin/perl -w
# MD5: multiple
# TEST: multiple

# Runs the same divide operation multiple times but with different
# --zero-divisor options

# PSEUDO-TEST: ../rwbag/rwbagcat --delimited=, ../../tests/bag1-v4.bag | sed 's/^/99,/' | ./rwaggbagbuild --fields=records,sipv4,sum-bytes --column-separator=, --output-path=/tmp/rwaggbagtool-divide-zero-max-ab1 && ../rwbag/rwbagcat --delimited=, ../../tests/bag2-v4.bag | sed 's/^/33,/' | ./rwaggbagbuild --fields=records,sipv4,sum-bytes --column-separator=, | ./rwaggbagtool --subtract /tmp/rwaggbagtool-divide-zero-max-ab1 - | ./rwaggbagtool --divide --zero-divisor-result=max /tmp/rwaggbagtool-divide-zero-max-ab1 - | ./rwaggbagcat

use strict;
use SiLKTests;
my $NAME = $0;
$NAME =~ s,.*/,,;

my $rwaggbagtool = check_silk_app('rwaggbagtool');
my $rwaggbagbuild = check_silk_app('rwaggbagbuild');
my $rwaggbagcat = check_silk_app('rwaggbagcat');
my $rwbagcat = check_silk_app('rwbagcat');
my %file;
$file{v4bag1} = get_data_or_exit77('v4bag1');
$file{v4bag2} = get_data_or_exit77('v4bag2');
my %temp;
$temp{ab1} = make_tempname('ab1');
$temp{ab2} = make_tempname('ab2');
$temp{ab3} = make_tempname('ab3');

my $cmd;
my $md5;

# Convert bag1-v4.bag to an AggBag
$cmd = ("$rwbagcat --delimited=, $file{v4bag1}"
        ." | sed 's/^/99,/'"
        ." | $rwaggbagbuild --fields=records,sipv4,sum-bytes"
        ." --column-separator=, --output-path=$temp{ab1}");
check_exit_status($cmd, 1)
    or die "$NAME: Error running rwbagcat | rwaggbagbuild\n";

# Convert bag2-v4.bag to an AggBag
$cmd = ("$rwbagcat --delimited=, $file{v4bag2}"
        ." | sed 's/^/33,/'"
        ." | $rwaggbagbuild --fields=records,sipv4,sum-bytes"
        ." --column-separator=, --output-path=$temp{ab2}");
check_exit_status($cmd, 1)
    or die "$NAME: Error running rwbagcat | rwaggbagbuild\n";

# Subtract the two AggBags
$cmd = ("$rwaggbagtool --output-path=$temp{ab3}"
        ." --subtract $temp{ab1} $temp{ab2}");
check_exit_status($cmd, 1)
    or die "$NAME: Error running rwaggbagtool\n";

# The following tests compute the quotient of the first AggBag with
# the difference AggBag.

# Compute the quotient with no --zero-divisor switch
$cmd = ("$rwaggbagtool --divide --output-path=/dev/null"
        ." $temp{ab1} $temp{ab3}");
check_exit_status($cmd, 1)
    and die "$NAME: rwaggbagtool command succeeded that should have failed\n";

# Compute the quotient with --zero-divisor=error (same as previous)
$cmd = ("$rwaggbagtool --divide --zero-divisor-result=error"
        ." --output-path=/dev/null"
        ." $temp{ab1} $temp{ab3}");
check_exit_status($cmd, 1)
    and die "$NAME: rwaggbagtool command succeeded that should have failed\n";

# Compute the quotient with --zero-divisor=nochange
$md5 = "66c03f0440f5faa8e0e2bbbd36fe7e31";
$cmd = ("$rwaggbagtool --divide --zero-divisor-result=nochange"
        ." $temp{ab1} $temp{ab3}"
        ." | $rwaggbagcat");
check_md5_output($md5, $cmd);

# Compute the quotient with --zero-divisor=max
$md5 = "70e476a57b0dc2d9b6e807a05717f29b";
$cmd = ("$rwaggbagtool --divide --zero-divisor-result=max"
        ." $temp{ab1} $temp{ab3}"
        ." | $rwaggbagcat");
check_md5_output($md5, $cmd);

# Compute the quotient with --zero-divisor=54321 (a value)
$md5 = "792b13006c3663062803304fcd55931c";
$cmd = ("$rwaggbagtool --divide --zero-divisor-result=54321"
        ." $temp{ab1} $temp{ab3}"
        ." | $rwaggbagcat");
check_md5_output($md5, $cmd);

# Compute the quotient with --zero-divisor=remove
$md5 = "aa1abfabdc395493f32b69a0dc67b873";
$cmd = ("$rwaggbagtool --divide --zero-divisor-result=remove"
        ." $temp{ab1} $temp{ab3}"
        ." | $rwaggbagcat");
check_md5_output($md5, $cmd);


