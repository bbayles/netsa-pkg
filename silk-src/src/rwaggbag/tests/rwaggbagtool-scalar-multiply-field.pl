#! /usr/bin/perl -w
# MD5: 7ff6cefda8c7e335587adf2fcbfcd97c
# TEST: ../rwbag/rwbagcat ../../tests/bag1-v4.bag | ./rwaggbagbuild --fields=sipv4,sum-bytes | ./rwaggbagtool --scalar-multiply=sum-bytes=2 | ./rwaggbagcat

use strict;
use SiLKTests;

my $rwaggbagtool = check_silk_app('rwaggbagtool');
my $rwaggbagbuild = check_silk_app('rwaggbagbuild');
my $rwaggbagcat = check_silk_app('rwaggbagcat');
my $rwbagcat = check_silk_app('rwbagcat');
my %file;
$file{v4bag1} = get_data_or_exit77('v4bag1');
my $cmd = "$rwbagcat $file{v4bag1} | $rwaggbagbuild --fields=sipv4,sum-bytes | $rwaggbagtool --scalar-multiply=sum-bytes=2 | $rwaggbagcat";
my $md5 = "7ff6cefda8c7e335587adf2fcbfcd97c";

check_md5_output($md5, $cmd);
