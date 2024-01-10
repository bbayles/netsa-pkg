#! /usr/bin/perl -w
# STATUS: OK
# TEST: ./rwaggbagtool --help-fields

use strict;
use SiLKTests;

my $rwaggbagtool = check_silk_app('rwaggbagtool');
my $cmd = "$rwaggbagtool --help-fields";

exit (check_exit_status($cmd) ? 0 : 1);
