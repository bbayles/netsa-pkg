#! /usr/bin/perl -w
# MD5: 58816e22863d1297a7142e771a421afb
# TEST: ./rwfglob --data-rootdir=. --print-missing --start-date=2009/02/12:12 --end-date=2009/02/12:14 --flowtypes=all/in,all/outweb 2>&1

use strict;
use SiLKTests;

my $rwfglob = check_silk_app('rwfglob');

my $cmd = "$rwfglob --data-rootdir=. --print-missing --start-date=2009/02/12:12 --end-date=2009/02/12:14 --flowtypes=all/in,all/outweb 2>&1";
my $md5 = "58816e22863d1297a7142e771a421afb";

check_md5_output($md5, $cmd);
