#! /usr/bin/perl -w
# MD5: 00c1411ac58b5fa576a2621b254e4343
# TEST: ./rwsiteinfo --fields=class,type --types=type1,@ --site-config-file ./tests/rwsiteinfo-site.conf

use strict;
use SiLKTests;

my $rwsiteinfo = check_silk_app('rwsiteinfo');

my $site_info = "$SiLKTests::srcdir/tests/rwsiteinfo-site.conf";
unless (-f $site_info) {
    skip_test("Did not find file '$site_info'");
}

my $cmd = "$rwsiteinfo --fields=class,type --types=type1,@ --site-config-file $SiLKTests::srcdir/tests/rwsiteinfo-site.conf";
my $md5 = "00c1411ac58b5fa576a2621b254e4343";

check_md5_output($md5, $cmd);
