#! /usr/bin/perl -w
# STATUS: OK
# TEST: ./rwaggbag --help-fields

use strict;
use SiLKTests;

my $rwaggbag = check_silk_app('rwaggbag');
my $cmd = "$rwaggbag --help-fields";

exit (check_exit_status($cmd) ? 0 : 1);
