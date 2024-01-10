#! /usr/bin/perl -w
# MD5: 2742c1f9fe641ec00a78925d0e29394b
# TEST: ./rwfglob --data-rootdir=. --print-missing --start-date=2009/02/12:12 --end-date=2009/02/12:14 2>&1

use strict;
use SiLKTests;

my $rwfglob = check_silk_app('rwfglob');

my $cmd = "$rwfglob --data-rootdir=. --print-missing --start-date=2009/02/12:12 --end-date=2009/02/12:14 2>&1";
my $md5 = "2742c1f9fe641ec00a78925d0e29394b";

check_md5_output($md5, $cmd);
