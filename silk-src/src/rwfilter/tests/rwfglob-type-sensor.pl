#! /usr/bin/perl -w
# MD5: 66dc2a712d6cbdda2f5da100f4c98161
# TEST: ./rwfglob --data-rootdir=. --print-missing --start-date=2009/02/12:12 --end-date=2009/02/12:14 --type=inweb --sensor=S12 2>&1

use strict;
use SiLKTests;

my $rwfglob = check_silk_app('rwfglob');

my $cmd = "$rwfglob --data-rootdir=. --print-missing --start-date=2009/02/12:12 --end-date=2009/02/12:14 --type=inweb --sensor=S12 2>&1";
my $md5 = "66dc2a712d6cbdda2f5da100f4c98161";

check_md5_output($md5, $cmd);
