#! /usr/bin/perl -w
# MD5: 474b7bef2d8a99be467022d71cfef890
# TEST: ./rwbagcat ../../tests/bag1-v4.bag ../../tests/bag1-v4.bag ../../tests/bag1-v4.bag | ./rwbagbuild --bag-input=- --key-type=sipv4 --counter-type=sum-bytes | ./rwbagcat

use strict;
use SiLKTests;

my $rwbagbuild = check_silk_app('rwbagbuild');
my $rwbagcat = check_silk_app('rwbagcat');
my %file;
$file{v4bag1} = get_data_or_exit77('v4bag1');
my $cmd = "$rwbagcat $file{v4bag1} $file{v4bag1} $file{v4bag1} | $rwbagbuild --bag-input=- --key-type=sipv4 --counter-type=sum-bytes | $rwbagcat";
my $md5 = "474b7bef2d8a99be467022d71cfef890";

check_md5_output($md5, $cmd);
