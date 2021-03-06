#! /usr/bin/perl -w
# MD5: 15a08f78a8eaa216b3de7ce4d1536334
# TEST: ./rwset --sip-file=stdout ../../tests/data-v6.rwf | ./rwsetcat --cidr-blocks=0

use strict;
use SiLKTests;

my $rwset = check_silk_app('rwset');
my $rwsetcat = check_silk_app('rwsetcat');
my %file;
$file{v6data} = get_data_or_exit77('v6data');
check_features(qw(ipset_v6));
my $cmd = "$rwset --sip-file=stdout $file{v6data} | $rwsetcat --cidr-blocks=0";
my $md5 = "15a08f78a8eaa216b3de7ce4d1536334";

check_md5_output($md5, $cmd);
