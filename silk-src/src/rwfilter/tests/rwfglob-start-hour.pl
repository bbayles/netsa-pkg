#! /usr/bin/perl -w
# MD5: fc22094df137270c14801488200042be
# TEST: ./rwfglob --data-rootdir=. --print-missing --start-date=2009/02/12:12 2>&1

use strict;
use SiLKTests;

my $rwfglob = check_silk_app('rwfglob');

my $cmd = "$rwfglob --data-rootdir=. --print-missing --start-date=2009/02/12:12 2>&1";
my $md5 = "fc22094df137270c14801488200042be";

check_md5_output($md5, $cmd);
