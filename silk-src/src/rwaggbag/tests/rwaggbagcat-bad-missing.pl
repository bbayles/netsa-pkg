#! /usr/bin/perl -w
# STATUS: ERR
# TEST: ./rwaggbagcat --mising-fields=protocol=0 /dev/null

use strict;
use SiLKTests;

my $rwaggbagcat = check_silk_app('rwaggbagcat');
my $cmd = "$rwaggbagcat --mising-fields=protocol=0 /dev/null";

exit (check_exit_status($cmd) ? 1 : 0);
