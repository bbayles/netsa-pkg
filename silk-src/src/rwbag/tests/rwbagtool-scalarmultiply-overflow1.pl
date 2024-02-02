#! /usr/bin/perl -w
# MD5: 789cf24b641efd7b87c5e57c6ada8a63
# TEST: echo 443,3689348814741910323 | ./rwbagbuild --bag-input=- --delimiter=, --key-type=sport --counter-type=sum-bytes | ./rwbagtool --scalar-multiply=5 | ./rwbagcat

use strict;
use SiLKTests;

my $rwbagtool = check_silk_app('rwbagtool');
my $rwbagbuild = check_silk_app('rwbagbuild');
my $rwbagcat = check_silk_app('rwbagcat');
my $cmd = "echo 443,3689348814741910323 | $rwbagbuild --bag-input=- --delimiter=, --key-type=sport --counter-type=sum-bytes | $rwbagtool --scalar-multiply=5 | $rwbagcat";
my $md5 = "789cf24b641efd7b87c5e57c6ada8a63";

check_md5_output($md5, $cmd);
