#! /usr/bin/perl -w
# MD5: 1659ee38467a3e76d0e71b6df397baeb
# TEST: ./rwsiteinfo --fields=sensor --site-config-file ./tests/rwsiteinfo-site.conf

use strict;
use SiLKTests;

my $rwsiteinfo = check_silk_app('rwsiteinfo');

my $site_info = "$SiLKTests::srcdir/tests/rwsiteinfo-site.conf";
unless (-f $site_info) {
    skip_test("Did not find file '$site_info'");
}

my $cmd = "$rwsiteinfo --fields=sensor --site-config-file $SiLKTests::srcdir/tests/rwsiteinfo-site.conf";
my $md5 = "1659ee38467a3e76d0e71b6df397baeb";

check_md5_output($md5, $cmd);
