#! /usr/bin/perl -w
# MD5: 2b996e4d61bc6ac96c13ee4a7db1c2c5
# TEST: ./rwfglob --data-rootdir=. --print-missing --start-date=2009/02/12:12 --end-date=2009/02/12:14 --sensors=@/tmp/sensor.txt 2>&1

use strict;
use SiLKTests;

my $rwfglob = check_silk_app('rwfglob');


# create our tempdir
my $tmpdir = make_tempdir();

# the file of sensors
my $sensor_file = "$tmpdir/sensor.txt";
my $sensor_text = <<'END_SENSOR';
# Sensor 4
   S4
# Sensors 6-8
S6, S7,S8

S10  # Sensor 10
END_SENSOR

make_config_file($sensor_file, \$sensor_text);
$sensor_file =~ s/([\@\,])/\@$1/g;

my $cmd = "$rwfglob --data-rootdir=. --print-missing --start-date=2009/02/12:12 --end-date=2009/02/12:14 --sensors=\@$sensor_file 2>&1";
my $md5 = "2b996e4d61bc6ac96c13ee4a7db1c2c5";

check_md5_output($md5, $cmd);
