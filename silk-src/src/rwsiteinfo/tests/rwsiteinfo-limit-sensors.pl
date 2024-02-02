#! /usr/bin/perl -w
# MD5: 2aaddeffe1d19b880d7a60ceffe42e3e
# TEST: ./rwsiteinfo --fields=sensor,class --sensors=3-5,17,S --site-config-file ./tests/rwsiteinfo-site.conf

use strict;
use SiLKTests;

my $rwsiteinfo = check_silk_app('rwsiteinfo');

my $site_info = "$SiLKTests::srcdir/tests/rwsiteinfo-site.conf";
unless (-f $site_info) {
    skip_test("Did not find file '$site_info'");
}

my $cmd = "$rwsiteinfo --fields=sensor,class --sensors=3-5,17,S --site-config-file $SiLKTests::srcdir/tests/rwsiteinfo-site.conf";
my $md5 = "2aaddeffe1d19b880d7a60ceffe42e3e";

check_md5_output($md5, $cmd);
