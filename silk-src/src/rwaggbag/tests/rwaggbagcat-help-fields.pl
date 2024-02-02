#! /usr/bin/perl -w
# STATUS: OK
# TEST: ./rwaggbagcat --help-fields

use strict;
use SiLKTests;

my $rwaggbagcat = check_silk_app('rwaggbagcat');
my $cmd = "$rwaggbagcat --help-fields";

exit (check_exit_status($cmd) ? 0 : 1);
