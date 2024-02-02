#! /usr/bin/perl -w
# MD5: 76f8432ff6a75f021156bc4a388270c9
# TEST: ../rwbag/rwbagcat ../../tests/bag1-v4.bag | ./rwaggbagbuild --fields=sipv4,sum-bytes --output-path=/tmp/rwaggbagtool-divide-aggbag1 && ../rwbag/rwbagcat ../../tests/bag3-v4.bag | ./rwaggbagbuild --fields=sipv4,sum-bytes | ./rwaggbagtool --divide /tmp/rwaggbagtool-divide-aggbag1 - | ./rwaggbagcat

use strict;
use SiLKTests;

my $rwaggbagtool = check_silk_app('rwaggbagtool');
my $rwaggbagbuild = check_silk_app('rwaggbagbuild');
my $rwaggbagcat = check_silk_app('rwaggbagcat');
my $rwbagcat = check_silk_app('rwbagcat');
my %file;
$file{v4bag1} = get_data_or_exit77('v4bag1');
$file{v4bag3} = get_data_or_exit77('v4bag3');
my %temp;
$temp{aggbag1} = make_tempname('aggbag1');
my $cmd = "$rwbagcat $file{v4bag1} | $rwaggbagbuild --fields=sipv4,sum-bytes --output-path=$temp{aggbag1} && $rwbagcat $file{v4bag3} | $rwaggbagbuild --fields=sipv4,sum-bytes | $rwaggbagtool --divide $temp{aggbag1} - | $rwaggbagcat";
my $md5 = "76f8432ff6a75f021156bc4a388270c9";

check_md5_output($md5, $cmd);
