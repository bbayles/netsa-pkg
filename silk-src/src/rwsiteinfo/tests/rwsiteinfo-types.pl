#! /usr/bin/perl -w
# MD5: 31d703812c2d857ca893eb57f6e18c4f
# TEST: ./rwsiteinfo --fields=type --site-config-file ./tests/rwsiteinfo-site.conf

use strict;
use SiLKTests;

my $rwsiteinfo = check_silk_app('rwsiteinfo');

my $site_info = "$SiLKTests::srcdir/tests/rwsiteinfo-site.conf";
unless (-f $site_info) {
    skip_test("Did not find file '$site_info'");
}

my $cmd = "$rwsiteinfo --fields=type --site-config-file $SiLKTests::srcdir/tests/rwsiteinfo-site.conf";
my $md5 = "31d703812c2d857ca893eb57f6e18c4f";

check_md5_output($md5, $cmd);
