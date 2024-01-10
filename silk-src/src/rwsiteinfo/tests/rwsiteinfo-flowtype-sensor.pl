#! /usr/bin/perl -w
# MD5: e289c3c35904e2803b30d0d82626c141
# TEST: ./rwsiteinfo --fields=flowtype,sensor --site-config-file ./tests/rwsiteinfo-site.conf

use strict;
use SiLKTests;

my $rwsiteinfo = check_silk_app('rwsiteinfo');

my $site_info = "$SiLKTests::srcdir/tests/rwsiteinfo-site.conf";
unless (-f $site_info) {
    skip_test("Did not find file '$site_info'");
}

my $cmd = "$rwsiteinfo --fields=flowtype,sensor --site-config-file $SiLKTests::srcdir/tests/rwsiteinfo-site.conf";
my $md5 = "e289c3c35904e2803b30d0d82626c141";

check_md5_output($md5, $cmd);
