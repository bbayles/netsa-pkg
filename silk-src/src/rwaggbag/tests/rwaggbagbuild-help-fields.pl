#! /usr/bin/perl -w
# STATUS: OK
# TEST: ./rwaggbagbuild --help-fields

use strict;
use SiLKTests;

my $rwaggbagbuild = check_silk_app('rwaggbagbuild');
my $cmd = "$rwaggbagbuild --help-fields";

exit (check_exit_status($cmd) ? 0 : 1);
