#! /usr/bin/perl -w
# MD5: abe0cef4cf0e94802d44e3a78994fcbc
# TEST: ./rwaggbag --key=protocol --counter=records,sum-bytes ../../tests/data.rwf | ./rwaggbagcat

use strict;
use SiLKTests;

my $rwaggbagcat = check_silk_app('rwaggbagcat');
my $rwaggbag = check_silk_app('rwaggbag');
my %file;
$file{data} = get_data_or_exit77('data');
my $cmd = "$rwaggbag --key=protocol --counter=records,sum-bytes $file{data} | $rwaggbagcat";
my $md5 = "abe0cef4cf0e94802d44e3a78994fcbc";

check_md5_output($md5, $cmd);
