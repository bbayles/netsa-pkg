#! /usr/bin/perl -w
# MD5: 88201a2f32ebbab13eca937ee33703e6
# TEST: ./rwaggbag --key=proto --counter=sum-bytes ../../tests/data.rwf --output-path=/tmp/rwaggbagtool-multiply-divide-protobytes && ./rwaggbagtool --scalar-multiply=10 /tmp/rwaggbagtool-multiply-divide-protobytes | ./rwaggbagtool --divide - /tmp/rwaggbagtool-multiply-divide-protobytes | ./rwaggbagcat

use strict;
use SiLKTests;

my $rwaggbagtool = check_silk_app('rwaggbagtool');
my $rwaggbag = check_silk_app('rwaggbag');
my $rwaggbagcat = check_silk_app('rwaggbagcat');
my %file;
$file{data} = get_data_or_exit77('data');
my %temp;
$temp{protobytes} = make_tempname('protobytes');
my $cmd = "$rwaggbag --key=proto --counter=sum-bytes $file{data} --output-path=$temp{protobytes} && $rwaggbagtool --scalar-multiply=10 $temp{protobytes} | $rwaggbagtool --divide - $temp{protobytes} | $rwaggbagcat";
my $md5 = "88201a2f32ebbab13eca937ee33703e6";

check_md5_output($md5, $cmd);
