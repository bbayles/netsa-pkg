#! /usr/bin/perl -w
# MD5: 14132cbd4d27b1d8dbc26204c17bca0b
# TEST: ./rwfglob --data-rootdir=. --print-missing --start-date=2009/02/12:12 --end-date=2009/02/12:14 --type=@/tmp/type.txt 2>&1

use strict;
use SiLKTests;

my $rwfglob = check_silk_app('rwfglob');


# create our tempdir
my $tmpdir = make_tempdir();

# the file of types
my $type_file = "$tmpdir/type.txt";
my $type_text = "    out    ";

make_config_file($type_file, \$type_text);
$type_file =~ s/([\@\,])/\@$1/g;

my $cmd = "$rwfglob --data-rootdir=. --print-missing --start-date=2009/02/12:12 --end-date=2009/02/12:14 --type=\@$type_file 2>&1";
my $md5 = "14132cbd4d27b1d8dbc26204c17bca0b";

check_md5_output($md5, $cmd);
