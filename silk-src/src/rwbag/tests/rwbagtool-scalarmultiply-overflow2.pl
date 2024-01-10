#! /usr/bin/perl -w
# MD5: 4c856e060320f5f31c08d94482e6df75
# TEST: echo 443,3689348814741910323 | ./rwbagbuild --bag-input=- --delimiter=, --key-type=sport --counter-type=sum-bytes | ./rwbagtool --scalar-multiply=6 | ./rwbagcat

use strict;
use SiLKTests;

my $rwbagtool = check_silk_app('rwbagtool');
my $rwbagbuild = check_silk_app('rwbagbuild');
my $rwbagcat = check_silk_app('rwbagcat');
my $cmd = "echo 443,3689348814741910323 | $rwbagbuild --bag-input=- --delimiter=, --key-type=sport --counter-type=sum-bytes | $rwbagtool --scalar-multiply=6 | $rwbagcat";
my $md5 = "4c856e060320f5f31c08d94482e6df75";

check_md5_output($md5, $cmd);
