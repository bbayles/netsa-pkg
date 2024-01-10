#! /usr/bin/perl -w
# MD5: e4bfe9a5a80b369c2ce291bad424c49a
# TEST: ./rwbagtool --modify-inplace --add ../../tests/bag1-v4.bag ../../tests/bag2-v4.bag | ./rwbagcat

use strict;
use SiLKTests;

my $rwbagtool = check_silk_app('rwbagtool');
my $rwbagcat = check_silk_app('rwbagcat');
my %file;
$file{v4bag1} = get_data_or_exit77('v4bag1');
$file{v4bag2} = get_data_or_exit77('v4bag2');
my $cmd = "$rwbagtool --modify-inplace --add $file{v4bag1} $file{v4bag2} | $rwbagcat";
my $md5 = "e4bfe9a5a80b369c2ce291bad424c49a";

check_md5_output($md5, $cmd);
