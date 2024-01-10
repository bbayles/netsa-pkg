#! /usr/bin/perl -w
# MD5: da14d3f2f81e95db8a23ef0a4b1a4b14
# TEST: ./parse-tests --tcp-flags 2>&1

use strict;
use SiLKTests;

my $parse_tests = check_silk_app('parse-tests');
my $cmd = "$parse_tests --tcp-flags 2>&1";
my $md5 = "da14d3f2f81e95db8a23ef0a4b1a4b14";

check_md5_output($md5, $cmd);
