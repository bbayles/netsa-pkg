#! /usr/bin/perl -w
# MD5: 3c2fec62e56bbb9dd3203c409efa3e73
# TEST: ./rwsiteinfo --fields=sensor,group --site-config-file ./tests/rwsiteinfo-site.conf

use strict;
use SiLKTests;

my $rwsiteinfo = check_silk_app('rwsiteinfo');

my $site_info = "$SiLKTests::srcdir/tests/rwsiteinfo-site.conf";
unless (-f $site_info) {
    skip_test("Did not find file '$site_info'");
}

my $cmd = "$rwsiteinfo --fields=sensor,group --site-config-file $SiLKTests::srcdir/tests/rwsiteinfo-site.conf";
my $md5 = "3c2fec62e56bbb9dd3203c409efa3e73";

check_md5_output($md5, $cmd);
