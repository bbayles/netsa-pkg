#! /usr/bin/perl -w
# MD5: 3499dec47021471ae880543e1b82522b
# TEST: ./rwsiteinfo --fields=sensor,class,group --sensors=SensorGroup4 --site-config-file ./tests/rwsiteinfo-site.conf

use strict;
use SiLKTests;

my $rwsiteinfo = check_silk_app('rwsiteinfo');

my $site_info = "$SiLKTests::srcdir/tests/rwsiteinfo-site.conf";
unless (-f $site_info) {
    skip_test("Did not find file '$site_info'");
}

my $cmd = "$rwsiteinfo --fields=sensor,class,group --sensors=SensorGroup4 --site-config-file $SiLKTests::srcdir/tests/rwsiteinfo-site.conf";
my $md5 = "3499dec47021471ae880543e1b82522b";

check_md5_output($md5, $cmd);
