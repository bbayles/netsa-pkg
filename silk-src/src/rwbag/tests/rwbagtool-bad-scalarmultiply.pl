#! /usr/bin/perl -w
# STATUS: ERR
# TEST: ./rwbagtool --scalar-multiply=18446744073709551615 --output-path=/dev/null /dev/null

use strict;
use SiLKTests;

my $rwbagtool = check_silk_app('rwbagtool');
my $cmd = "$rwbagtool --scalar-multiply=18446744073709551615 --output-path=/dev/null /dev/null";

exit (check_exit_status($cmd) ? 1 : 0);
