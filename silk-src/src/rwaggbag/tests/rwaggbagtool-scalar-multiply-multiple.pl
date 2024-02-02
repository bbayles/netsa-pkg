#! /usr/bin/perl -w
# MD5: 91c5744715d938890f27b00ce7de203b
# TEST: ./rwaggbag --key=sport,dport,proto --counter=sum-bytes,sum-packets,records ../../tests/data.rwf | ./rwaggbagtool --scalar-multiply records=2 --scalar-multiply sum-packets=0 --scalar-multiply 5 --scalar-multiply records=2 | ./rwaggbagcat

use strict;
use SiLKTests;

my $rwaggbagtool = check_silk_app('rwaggbagtool');
my $rwaggbag = check_silk_app('rwaggbag');
my $rwaggbagcat = check_silk_app('rwaggbagcat');
my %file;
$file{data} = get_data_or_exit77('data');
my $cmd = "$rwaggbag --key=sport,dport,proto --counter=sum-bytes,sum-packets,records $file{data} | $rwaggbagtool --scalar-multiply records=2 --scalar-multiply sum-packets=0 --scalar-multiply 5 --scalar-multiply records=2 | $rwaggbagcat";
my $md5 = "91c5744715d938890f27b00ce7de203b";

check_md5_output($md5, $cmd);
