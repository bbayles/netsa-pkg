#! /usr/bin/perl -w
# MD5: f2bcdae89f872389c74b1641256e2ab6
# TEST: ./rwsiteinfo --fields=sensor,class,group --groups=SensorGroup4 --site-config-file ./tests/rwsiteinfo-site.conf

use strict;
use SiLKTests;

my $rwsiteinfo = check_silk_app('rwsiteinfo');

my $site_info = "$SiLKTests::srcdir/tests/rwsiteinfo-site.conf";
unless (-f $site_info) {
    skip_test("Did not find file '$site_info'");
}

my $cmd = "$rwsiteinfo --fields=sensor,class,group --groups=SensorGroup4 --site-config-file $SiLKTests::srcdir/tests/rwsiteinfo-site.conf";
my $md5 = "f2bcdae89f872389c74b1641256e2ab6";

check_md5_output($md5, $cmd);
