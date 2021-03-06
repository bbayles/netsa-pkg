#! /usr/bin/perl -w
# MD5: 561213d99b5de94eb563d52bc71b0df1
# TEST: ./rwset --sip-file=stdout ../../tests/data.rwf | ./rwsetcat --network-structure

use strict;
use SiLKTests;

my $rwsetcat = check_silk_app('rwsetcat');
my $rwset = check_silk_app('rwset');
my %file;
$file{data} = get_data_or_exit77('data');
my $cmd = "$rwset --sip-file=stdout $file{data} | $rwsetcat --network-structure";
my $md5 = "561213d99b5de94eb563d52bc71b0df1";

check_md5_output($md5, $cmd);
