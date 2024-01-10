#! /usr/bin/perl -w
# MD5: 266c6d33666af3ecd03ac3bb03a55dcc
# TEST: ./rwsiteinfo --fields=default-type --site-config-file ./tests/rwsiteinfo-site.conf

use strict;
use SiLKTests;

my $rwsiteinfo = check_silk_app('rwsiteinfo');

my $site_info = "$SiLKTests::srcdir/tests/rwsiteinfo-site.conf";
unless (-f $site_info) {
    skip_test("Did not find file '$site_info'");
}

my $cmd = "$rwsiteinfo --fields=default-type --site-config-file $SiLKTests::srcdir/tests/rwsiteinfo-site.conf";
my $md5 = "266c6d33666af3ecd03ac3bb03a55dcc";

check_md5_output($md5, $cmd);
