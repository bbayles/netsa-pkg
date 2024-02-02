#! /usr/bin/perl -w
# MD5: 2b996e4d61bc6ac96c13ee4a7db1c2c5
# TEST: ./rwfglob --data-rootdir=. --print-missing --start-date=2009/02/12:12 --end-date=2009/02/12:14 --sensors=S4,S6,S7,S8,S10 2>&1

use strict;
use SiLKTests;

my $rwfglob = check_silk_app('rwfglob');

my $cmd = "$rwfglob --data-rootdir=. --print-missing --start-date=2009/02/12:12 --end-date=2009/02/12:14 --sensors=S4,S6,S7,S8,S10 2>&1";
my $md5 = "2b996e4d61bc6ac96c13ee4a7db1c2c5";

check_md5_output($md5, $cmd);
