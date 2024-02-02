#! /usr/bin/perl -w
# MD5: a101549c948cc0e48db4616ac8a3d321
# TEST: ./rwaggbag --key=sport,dport,proto --counter=records ../../tests/data.rwf | ./rwaggbagtool --scalar-multiply 4294967296 --scalar-multiply 4294967296 | ./rwaggbagcat

use strict;
use SiLKTests;

my $rwaggbagtool = check_silk_app('rwaggbagtool');
my $rwaggbag = check_silk_app('rwaggbag');
my $rwaggbagcat = check_silk_app('rwaggbagcat');
my %file;
$file{data} = get_data_or_exit77('data');
my $cmd = "$rwaggbag --key=sport,dport,proto --counter=records $file{data} | $rwaggbagtool --scalar-multiply 4294967296 --scalar-multiply 4294967296 | $rwaggbagcat";
my $md5 = "a101549c948cc0e48db4616ac8a3d321";

check_md5_output($md5, $cmd);
