#! /usr/bin/perl -w
# STATUS: ERR
# TEST: echo 443,18446744073709551615 | ./rwbagbuild --bag-input=- --delimiter-, --key-type=sport --counter-type=sum-bytes --output-path=/dev/null

use strict;
use SiLKTests;

my $rwbagbuild = check_silk_app('rwbagbuild');
my $cmd = "echo 443,18446744073709551615 | $rwbagbuild --bag-input=- --delimiter-, --key-type=sport --counter-type=sum-bytes --output-path=/dev/null";

exit (check_exit_status($cmd) ? 1 : 0);
