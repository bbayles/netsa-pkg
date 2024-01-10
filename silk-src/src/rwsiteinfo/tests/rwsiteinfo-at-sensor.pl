#! /usr/bin/perl -w
# MD5: 824cecb294718a3b5ceef3c3735d2927
# TEST: ./rwsiteinfo --delimited --fields=class,type,sensor --sensors=@./tests/at-sensor.txt --site-config-file ./tests/rwsiteinfo-site.conf

use strict;
use SiLKTests;

my $rwsiteinfo = check_silk_app('rwsiteinfo');

my $at_sensor = "$SiLKTests::srcdir/tests/at-sensor.txt";
unless (-f $at_sensor) {
    skip_test("Did not find file '$at_sensor'");
}
$at_sensor =~ s/([\@\,])/\@$1/g;

my $site_info = "$SiLKTests::srcdir/tests/rwsiteinfo-site.conf";
unless (-f $site_info) {
    skip_test("Did not find file '$site_info'");
}

my $cmd = "$rwsiteinfo --delimited --fields=class,type,sensor --sensors=\@$at_sensor --site-config-file $SiLKTests::srcdir/tests/rwsiteinfo-site.conf";
my $md5 = "824cecb294718a3b5ceef3c3735d2927";

check_md5_output($md5, $cmd);
