#! /usr/bin/perl -w
# STATUS: OK
# TEST: ./rwaggbagbuild --fields=sipv4,sum-bytes /dev/null | ./rwaggbagtool --scalar-multiply=sipv4=1000 --output-path=/dev/null

use strict;
use SiLKTests;

my $rwaggbagtool = check_silk_app('rwaggbagtool');
my $rwaggbagbuild = check_silk_app('rwaggbagbuild');
my $cmd = "$rwaggbagbuild --fields=sipv4,sum-bytes /dev/null | $rwaggbagtool --scalar-multiply=sipv4=1000 --output-path=/dev/null";

exit (check_exit_status($cmd) ? 0 : 1);
