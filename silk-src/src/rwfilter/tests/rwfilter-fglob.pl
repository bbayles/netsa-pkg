#! /usr/bin/perl -w
# MD5: 388ee36e337d4aa64d7ed1d8376d34bc
# TEST: ./rwfilter --data-rootdir=. --print-missing --start-date=2009/02/12:12 --end-date=2009/02/12:14 --sensors=S4,S6,S7,S8,S10 --type=in,outweb --all=/dev/null 2>&1

use strict;
use SiLKTests;

my $rwfilter = check_silk_app('rwfilter');

my $cmd = "$rwfilter --data-rootdir=. --print-missing --start-date=2009/02/12:12 --end-date=2009/02/12:14 --sensors=S4,S6,S7,S8,S10 --type=in,outweb --all=/dev/null 2>&1";
my $md5 = "388ee36e337d4aa64d7ed1d8376d34bc";

check_md5_output($md5, $cmd);
