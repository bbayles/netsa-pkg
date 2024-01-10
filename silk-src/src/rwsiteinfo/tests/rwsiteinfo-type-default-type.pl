#! /usr/bin/perl -w
# MD5: 18018539f860baf73f9ac96dfa22faf0
# TEST: ./rwsiteinfo --fields=type,default-type --site-config-file ./tests/rwsiteinfo-site.conf

use strict;
use SiLKTests;

my $rwsiteinfo = check_silk_app('rwsiteinfo');

my $site_info = "$SiLKTests::srcdir/tests/rwsiteinfo-site.conf";
unless (-f $site_info) {
    skip_test("Did not find file '$site_info'");
}

my $cmd = "$rwsiteinfo --fields=type,default-type --site-config-file $SiLKTests::srcdir/tests/rwsiteinfo-site.conf";
my $md5 = "18018539f860baf73f9ac96dfa22faf0";

check_md5_output($md5, $cmd);
