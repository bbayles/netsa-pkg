#! /usr/bin/perl -w
# MD5: e8f910c766b0bc8c6185b633a51730ec
# TEST: ./rwsiteinfo --fields=flowtype --site-config-file ./tests/rwsiteinfo-site.conf

use strict;
use SiLKTests;

my $rwsiteinfo = check_silk_app('rwsiteinfo');

my $site_info = "$SiLKTests::srcdir/tests/rwsiteinfo-site.conf";
unless (-f $site_info) {
    skip_test("Did not find file '$site_info'");
}

my $cmd = "$rwsiteinfo --fields=flowtype --site-config-file $SiLKTests::srcdir/tests/rwsiteinfo-site.conf";
my $md5 = "e8f910c766b0bc8c6185b633a51730ec";

check_md5_output($md5, $cmd);
