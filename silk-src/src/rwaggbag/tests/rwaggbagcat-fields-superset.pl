#! /usr/bin/perl -w
# MD5: 3493b81546be99a96632e96ddfe0c200
# TEST: ./rwaggbag --key=protocol --counter=records,sum-bytes ../../tests/data.rwf | ./rwaggbagcat --fields=sport,protocol,sum-bytes,records

use strict;
use SiLKTests;

my $rwaggbagcat = check_silk_app('rwaggbagcat');
my $rwaggbag = check_silk_app('rwaggbag');
my %file;
$file{data} = get_data_or_exit77('data');
my $cmd = "$rwaggbag --key=protocol --counter=records,sum-bytes $file{data} | $rwaggbagcat --fields=sport,protocol,sum-bytes,records";
my $md5 = "3493b81546be99a96632e96ddfe0c200";

check_md5_output($md5, $cmd);
