#! /usr/bin/perl -w
# MD5: c412b5e46143e9ddfcb83f07247dc357
# TEST: ./rwsiteinfo --fields=class,sensor --site-config-file ./tests/rwsiteinfo-site.conf

use strict;
use SiLKTests;

my $rwsiteinfo = check_silk_app('rwsiteinfo');

my $site_info = "$SiLKTests::srcdir/tests/rwsiteinfo-site.conf";
unless (-f $site_info) {
    skip_test("Did not find file '$site_info'");
}

my $cmd = "$rwsiteinfo --fields=class,sensor --site-config-file $SiLKTests::srcdir/tests/rwsiteinfo-site.conf";
my $md5 = "c412b5e46143e9ddfcb83f07247dc357";

check_md5_output($md5, $cmd);
