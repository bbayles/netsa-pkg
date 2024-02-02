#! /usr/bin/perl -w
# MD5: e4bfe9a5a80b369c2ce291bad424c49a
# TEST: ./rwbagtool --modify-inplace --output-path=/tmp/rwbagtool-inplace-noexist-output --add ../../tests/bag1-v4.bag ../../tests/bag2-v4.bag && ./rwbagcat /tmp/rwbagtool-inplace-noexist-output

use strict;
use SiLKTests;

my $rwbagtool = check_silk_app('rwbagtool');
my $rwbagcat = check_silk_app('rwbagcat');
my %file;
$file{v4bag1} = get_data_or_exit77('v4bag1');
$file{v4bag2} = get_data_or_exit77('v4bag2');
my %temp;
$temp{output} = make_tempname('output');
my $cmd = "$rwbagtool --modify-inplace --output-path=$temp{output} --add $file{v4bag1} $file{v4bag2} && $rwbagcat $temp{output}";
my $md5 = "e4bfe9a5a80b369c2ce291bad424c49a";

check_md5_output($md5, $cmd);
