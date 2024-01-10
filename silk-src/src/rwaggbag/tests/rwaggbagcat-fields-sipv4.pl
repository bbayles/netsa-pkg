#! /usr/bin/perl -w
# MD5: c5ffbcfdf490ab4e877438cd23d23b6f
# TEST: ./rwaggbag --key=sipv4,protocol --counter=records ../../tests/data.rwf | ./rwaggbagcat --fields=sipv4,protocol,records

use strict;
use SiLKTests;

my $rwaggbagcat = check_silk_app('rwaggbagcat');
my $rwaggbag = check_silk_app('rwaggbag');
my %file;
$file{data} = get_data_or_exit77('data');
my $cmd = "$rwaggbag --key=sipv4,protocol --counter=records $file{data} | $rwaggbagcat --fields=sipv4,protocol,records";
my $md5 = "c5ffbcfdf490ab4e877438cd23d23b6f";

check_md5_output($md5, $cmd);
