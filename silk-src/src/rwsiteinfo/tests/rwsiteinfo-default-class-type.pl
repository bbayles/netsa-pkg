#! /usr/bin/perl -w
# MD5: 6601e7d4e85bacb4134020168375e439
# TEST: ./rwsiteinfo --fields=default-class,type --site-config-file ./tests/rwsiteinfo-site.conf

use strict;
use SiLKTests;

my $rwsiteinfo = check_silk_app('rwsiteinfo');

my $site_info = "$SiLKTests::srcdir/tests/rwsiteinfo-site.conf";
unless (-f $site_info) {
    skip_test("Did not find file '$site_info'");
}

my $cmd = "$rwsiteinfo --fields=default-class,type --site-config-file $SiLKTests::srcdir/tests/rwsiteinfo-site.conf";
my $md5 = "6601e7d4e85bacb4134020168375e439";

check_md5_output($md5, $cmd);
