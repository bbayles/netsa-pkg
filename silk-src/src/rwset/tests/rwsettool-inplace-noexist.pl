#! /usr/bin/perl -w
# MD5: fb63420d9993e09e4d02e1857a22a7f2
# TEST: ./rwsettool --modify-inplace --output-path=/tmp/rwsettool-inplace-noexist-output --union ../../tests/set1-v4.set ../../tests/set2-v4.set && ./rwsetcat --cidr /tmp/rwsettool-inplace-noexist-output

use strict;
use SiLKTests;

my $rwsettool = check_silk_app('rwsettool');
my $rwsetcat = check_silk_app('rwsetcat');
my %file;
$file{v4set1} = get_data_or_exit77('v4set1');
$file{v4set2} = get_data_or_exit77('v4set2');
my %temp;
$temp{output} = make_tempname('output');
my $cmd = "$rwsettool --modify-inplace --output-path=$temp{output} --union $file{v4set1} $file{v4set2} && $rwsetcat --cidr $temp{output}";
my $md5 = "fb63420d9993e09e4d02e1857a22a7f2";

check_md5_output($md5, $cmd);
