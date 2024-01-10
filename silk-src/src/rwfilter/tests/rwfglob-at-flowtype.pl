#! /usr/bin/perl -w
# MD5: 58816e22863d1297a7142e771a421afb
# TEST: ./rwfglob --data-rootdir=. --print-missing --start-date=2009/02/12:12 --end-date=2009/02/12:14 --flowtypes=@/tmp/flowtype.txt 2>&1

use strict;
use SiLKTests;

my $rwfglob = check_silk_app('rwfglob');


# create our tempdir
my $tmpdir = make_tempdir();

# the file of flowtypes
my $flowtype_file = "$tmpdir/flowtype.txt";
my $flowtype_text = "    \nall/in\nall/outweb\n    \n";

make_config_file($flowtype_file, \$flowtype_text);
$flowtype_file =~ s/([\@\,])/\@$1/g;

my $cmd = "$rwfglob --data-rootdir=. --print-missing --start-date=2009/02/12:12 --end-date=2009/02/12:14 --flowtypes=\@$flowtype_file 2>&1";
my $md5 = "58816e22863d1297a7142e771a421afb";

check_md5_output($md5, $cmd);
