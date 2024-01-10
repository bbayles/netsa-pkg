#! /usr/bin/perl -w
# STATUS: ERR
# TEST: echo 17,1771 | ./rwaggbagbuild --fields=protocol,records --columns-separator=, | ./rwaggbagcat --fields=protocol,records --missing-field=sport=0

use strict;
use SiLKTests;

my $rwaggbagcat = check_silk_app('rwaggbagcat');
my $rwaggbagbuild = check_silk_app('rwaggbagbuild');
my $cmd = "echo 17,1771 | $rwaggbagbuild --fields=protocol,records --columns-separator=, | $rwaggbagcat --fields=protocol,records --missing-field=sport=0";

exit (check_exit_status($cmd) ? 1 : 0);
