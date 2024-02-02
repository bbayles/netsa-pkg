#! /usr/bin/perl -w
# MD5: ff409a22606b52f67a128cd658b7b3c3
# TEST: ./rwaggbag --key=sipv6,protocol --counter=records ../../tests/data.rwf | ./rwaggbagcat --fields=sipv6,protocol,records

use strict;
use SiLKTests;

my $rwaggbagcat = check_silk_app('rwaggbagcat');
my $rwaggbag = check_silk_app('rwaggbag');
my %file;
$file{data} = get_data_or_exit77('data');
check_features(qw(ipv6));
my $cmd = "$rwaggbag --key=sipv6,protocol --counter=records $file{data} | $rwaggbagcat --fields=sipv6,protocol,records";
my $md5 = "ff409a22606b52f67a128cd658b7b3c3";

check_md5_output($md5, $cmd);
