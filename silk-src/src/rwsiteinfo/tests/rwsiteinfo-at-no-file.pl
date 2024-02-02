#! /usr/bin/perl -w
# ERR_MD5: d41d8cd98f00b204e9800998ecf8427e
# TEST: ./rwsiteinfo --delimited --fields=class,type,sensor --sensors=Sensor1,@at-no-file.txt,5 --site-config-file ./tests/rwsiteinfo-site.conf

use strict;
use SiLKTests;

my $rwsiteinfo = check_silk_app('rwsiteinfo');

my $site_info = "$SiLKTests::srcdir/tests/rwsiteinfo-site.conf";
unless (-f $site_info) {
    skip_test("Did not find file '$site_info'");
}

my $cmd = "$rwsiteinfo --delimited --fields=class,type,sensor --sensors=Sensor1,\@at-no-file.txt,5 --site-config-file $SiLKTests::srcdir/tests/rwsiteinfo-site.conf";
my $md5 = "d41d8cd98f00b204e9800998ecf8427e";

check_md5_output($md5, $cmd, 1);
