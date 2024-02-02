#! /usr/bin/perl -w
# MD5: 14132cbd4d27b1d8dbc26204c17bca0b
# TEST: ./rwfglob --data-rootdir=. --print-missing --start-date=2009/02/12:12 --end-date=2009/02/12:14 --type=out 2>&1

use strict;
use SiLKTests;

my $rwfglob = check_silk_app('rwfglob');

my $cmd = "$rwfglob --data-rootdir=. --print-missing --start-date=2009/02/12:12 --end-date=2009/02/12:14 --type=out 2>&1";
my $md5 = "14132cbd4d27b1d8dbc26204c17bca0b";

check_md5_output($md5, $cmd);
