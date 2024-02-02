#! /usr/bin/perl -w
# MD5: fa4980304e68ab1a62b2e24366c80ba1
# TEST: ./rwaggbag --key=sport --counter=records --output-path=/tmp/rwaggbagtool-inplace-noexist-sport_rec ../../tests/data.rwf && ./rwaggbagtool --modify-inplace --output-path=/tmp/rwaggbagtool-inplace-noexist-output --add /tmp/rwaggbagtool-inplace-noexist-sport_rec && ./rwaggbagcat /tmp/rwaggbagtool-inplace-noexist-output

use strict;
use SiLKTests;

my $rwaggbagtool = check_silk_app('rwaggbagtool');
my $rwaggbag = check_silk_app('rwaggbag');
my $rwaggbagcat = check_silk_app('rwaggbagcat');
my %file;
$file{data} = get_data_or_exit77('data');
my %temp;
$temp{sport_rec} = make_tempname('sport_rec');
$temp{output} = make_tempname('output');
my $cmd = "$rwaggbag --key=sport --counter=records --output-path=$temp{sport_rec} $file{data} && $rwaggbagtool --modify-inplace --output-path=$temp{output} --add $temp{sport_rec} && $rwaggbagcat $temp{output}";
my $md5 = "fa4980304e68ab1a62b2e24366c80ba1";

check_md5_output($md5, $cmd);
