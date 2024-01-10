#! /usr/bin/perl -w
# MD5: 1003ee3fe09f75d774ae46ea52cff8d3
# TEST: ./rwaggbag --key=protocol --counter=records,sum-bytes ../../tests/data.rwf | ./rwaggbagcat --fields=records,protocol

use strict;
use SiLKTests;

my $rwaggbagcat = check_silk_app('rwaggbagcat');
my $rwaggbag = check_silk_app('rwaggbag');
my %file;
$file{data} = get_data_or_exit77('data');
my $cmd = "$rwaggbag --key=protocol --counter=records,sum-bytes $file{data} | $rwaggbagcat --fields=records,protocol";
my $md5 = "1003ee3fe09f75d774ae46ea52cff8d3";

check_md5_output($md5, $cmd);
