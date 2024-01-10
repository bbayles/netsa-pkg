#! /usr/bin/perl -w
# MD5: d5b94581810ac25fc870ca7b7d74b2b1
# TEST: ./rwaggbag --key=protocol --counter=records,sum-bytes ../../tests/data.rwf | ./rwaggbagcat --fields=sport,dport,protocol,sum-bytes,records --missing dport=0 --missing sport=n/a

use strict;
use SiLKTests;

my $rwaggbagcat = check_silk_app('rwaggbagcat');
my $rwaggbag = check_silk_app('rwaggbag');
my %file;
$file{data} = get_data_or_exit77('data');
my $cmd = "$rwaggbag --key=protocol --counter=records,sum-bytes $file{data} | $rwaggbagcat --fields=sport,dport,protocol,sum-bytes,records --missing dport=0 --missing sport=n/a";
my $md5 = "d5b94581810ac25fc870ca7b7d74b2b1";

check_md5_output($md5, $cmd);
