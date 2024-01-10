#! /usr/bin/perl -w
# MD5: b49ef6f296433349860d223598c48a3b
# TEST: ./rwfglob --data-rootdir=. --print-missing --start-date=2009/02/13 --no-summary 2>&1

use strict;
use SiLKTests;

my $rwfglob = check_silk_app('rwfglob');

my $cmd = "$rwfglob --data-rootdir=. --print-missing --start-date=2009/02/13 --no-summary 2>&1";
my $md5 = "b49ef6f296433349860d223598c48a3b";

check_md5_output($md5, $cmd);
