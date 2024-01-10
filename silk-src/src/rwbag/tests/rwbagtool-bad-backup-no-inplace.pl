#! /usr/bin/perl -w
# STATUS: ERR
# TEST: ./rwbagtool --backup-path=/tmp/rwbagtool-bad-backup-no-inplace-backup --output-path=/dev/null --add ../../tests/bag1-v4.bag >/dev/null

use strict;
use SiLKTests;

my $rwbagtool = check_silk_app('rwbagtool');
my %file;
$file{v4bag1} = get_data_or_exit77('v4bag1');
my %temp;
$temp{backup} = make_tempname('backup');
my $cmd = "$rwbagtool --backup-path=$temp{backup} --output-path=/dev/null --add $file{v4bag1} >/dev/null";

exit (check_exit_status($cmd) ? 1 : 0);
