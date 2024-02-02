#! /usr/bin/perl -w
# MD5: 317340a4dd676cf6680ec2656447b040
# TEST: ./rwfilter --flags-session=pa/- --pass=stdout ../../tests/data.rwf | ../rwcat/rwcat --compression-method=none --byte-order=little --ipv4-output

use strict;
use SiLKTests;

my $rwfilter = check_silk_app('rwfilter');
my $rwcat = check_silk_app('rwcat');
my %file;
$file{data} = get_data_or_exit77('data');
my $cmd = "$rwfilter --flags-session=pa/- --pass=stdout $file{data} | $rwcat --compression-method=none --byte-order=little --ipv4-output";
my $md5 = "317340a4dd676cf6680ec2656447b040";

check_md5_output($md5, $cmd);
