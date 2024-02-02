#! /usr/bin/perl -w
# STATUS: ERR
# TEST: ./rwaggbag --key=sport --counter=records ../../tests/data.rwf | ./rwaggbagtool --backup-path=/tmp/rwaggbagtool-bad-backup-no-inplace-backup --output-path=/dev/null --add - >/dev/null

use strict;
use SiLKTests;

my $rwaggbagtool = check_silk_app('rwaggbagtool');
my $rwaggbag = check_silk_app('rwaggbag');
my %file;
$file{data} = get_data_or_exit77('data');
my %temp;
$temp{backup} = make_tempname('backup');
my $cmd = "$rwaggbag --key=sport --counter=records $file{data} | $rwaggbagtool --backup-path=$temp{backup} --output-path=/dev/null --add - >/dev/null";

exit (check_exit_status($cmd) ? 1 : 0);
