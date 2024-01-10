#! /usr/bin/perl -w
# MD5: 7043c804e1bbbf69e4675ac9a4aa65f7
# TEST: ./rwsiteinfo --fields=class,default-type --site-config-file ./tests/rwsiteinfo-site.conf

use strict;
use SiLKTests;

my $rwsiteinfo = check_silk_app('rwsiteinfo');

my $site_info = "$SiLKTests::srcdir/tests/rwsiteinfo-site.conf";
unless (-f $site_info) {
    skip_test("Did not find file '$site_info'");
}

my $cmd = "$rwsiteinfo --fields=class,default-type --site-config-file $SiLKTests::srcdir/tests/rwsiteinfo-site.conf";
my $md5 = "7043c804e1bbbf69e4675ac9a4aa65f7";

check_md5_output($md5, $cmd);
