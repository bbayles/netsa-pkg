#! /usr/bin/perl -w
# MD5: 4012afd69be5ee993c865ea8ad67bd62
# TEST: ./rwfilter --flags-session=/F,C/C --pass=stdout ../../tests/data.rwf | ../rwcat/rwcat --compression-method=none --byte-order=little --ipv4-output

use strict;
use SiLKTests;

my $rwfilter = check_silk_app('rwfilter');
my $rwcat = check_silk_app('rwcat');
my %file;
$file{data} = get_data_or_exit77('data');
my $cmd = "$rwfilter --flags-session=/F,C/C --pass=stdout $file{data} | $rwcat --compression-method=none --byte-order=little --ipv4-output";
my $md5 = "4012afd69be5ee993c865ea8ad67bd62";

check_md5_output($md5, $cmd);
