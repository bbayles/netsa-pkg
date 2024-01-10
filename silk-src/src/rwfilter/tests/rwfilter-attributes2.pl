#! /usr/bin/perl -w
# MD5: 78407ba5e55023dbc95c2aa014ae3b32
# TEST: ./rwfilter --attributes=c/- --pass=stdout ../../tests/data.rwf | ../rwcat/rwcat --compression-method=none --byte-order=little --ipv4-output

use strict;
use SiLKTests;

my $rwfilter = check_silk_app('rwfilter');
my $rwcat = check_silk_app('rwcat');
my %file;
$file{data} = get_data_or_exit77('data');
my $cmd = "$rwfilter --attributes=c/- --pass=stdout $file{data} | $rwcat --compression-method=none --byte-order=little --ipv4-output";
my $md5 = "78407ba5e55023dbc95c2aa014ae3b32";

check_md5_output($md5, $cmd);
