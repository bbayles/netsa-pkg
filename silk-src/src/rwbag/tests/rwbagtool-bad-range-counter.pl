#! /usr/bin/perl -w
# STATUS: ERR
# TEST: ./rwbagtool --mincounter=101 --maxcounter=99 --output-path=/dev/null /dev/null

use strict;
use SiLKTests;

my $rwbagtool = check_silk_app('rwbagtool');
my $cmd = "$rwbagtool --mincounter=101 --maxcounter=99 --output-path=/dev/null /dev/null";

exit (check_exit_status($cmd) ? 1 : 0);
