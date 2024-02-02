#! /usr/bin/perl -w
# MD5: 388ee36e337d4aa64d7ed1d8376d34bc
# TEST: ./rwfilter --data-rootdir=. --print-missing --start-date=2009/02/12:12 --end-date=2009/02/12:14 --sensors=@/tmp/sensor2.txt --type=@/tmp/type.txt --all=/dev/null 2>&1

use strict;
use SiLKTests;

my $rwfilter = check_silk_app('rwfilter');


# create our tempdir
my $tmpdir = make_tempdir();

# the file of types
my $type_file = "$tmpdir/type.txt";
my $type_text = "  in  \n  outweb  \n";

make_config_file($type_file, \$type_text);
$type_file =~ s/([\@\,])/\@$1/g;

# there are two files of sensors
my $sensor_file1 = "$tmpdir/sensor1.txt";
my $sensor_text1 = <<'END_SENSOR1';
# sensor 4
S4
# sensors 6,7
   S6,S7
END_SENSOR1

make_config_file($sensor_file1, \$sensor_text1);
$sensor_file1 =~ s/([\@\,])/\@$1/g;

my $sensor_file2 = "$tmpdir/sensor2.txt";
my $sensor_text2 = <<'END_SENSOR2';
,,,,,S8,,,,,  # sensor 8
# sensor 10
   S10
END_SENSOR2

make_config_file($sensor_file2, \$sensor_text2);
$sensor_file2 =~ s/([\@\,])/\@$1/g;

my $cmd = "$rwfilter --data-rootdir=. --print-missing --start-date=2009/02/12:12 --end-date=2009/02/12:14 --sensors=\@$sensor_file1,\@$sensor_file2 --type=\@$type_file --all=/dev/null 2>&1";
my $md5 = "388ee36e337d4aa64d7ed1d8376d34bc";

check_md5_output($md5, $cmd);
