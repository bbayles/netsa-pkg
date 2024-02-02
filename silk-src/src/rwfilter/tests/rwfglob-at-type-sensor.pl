#! /usr/bin/perl -w
# MD5: 66dc2a712d6cbdda2f5da100f4c98161
# TEST: ./rwfglob --data-rootdir=. --print-missing --start-date=2009/02/12:12 --end-date=2009/02/12:14 --type=@/tmp/type.txt --sensor=@/tmp/sensor.txt 2>&1

use strict;
use SiLKTests;

my $rwfglob = check_silk_app('rwfglob');


# create our tempdir
my $tmpdir = make_tempdir();

# the file of types
my $type_file = "$tmpdir/type.txt";
my $type_text = "inweb";

make_config_file($type_file, \$type_text);
$type_file =~ s/([\@\,])/\@$1/g;

# the file of sensors
my $sensor_file = "$tmpdir/sensor.txt";
my $sensor_text = "S12";

make_config_file($sensor_file, \$sensor_text);
$sensor_file =~ s/([\@\,])/\@$1/g;

my $cmd = "$rwfglob --data-rootdir=. --print-missing --start-date=2009/02/12:12 --end-date=2009/02/12:14 --type=\@$type_file --sensor=\@$sensor_file 2>&1";
my $md5 = "66dc2a712d6cbdda2f5da100f4c98161";

check_md5_output($md5, $cmd);
