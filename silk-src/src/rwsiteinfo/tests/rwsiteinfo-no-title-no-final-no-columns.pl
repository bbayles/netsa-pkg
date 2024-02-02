#! /usr/bin/perl -w
# MD5: 7d96db798427fc17e7fa27ff80993f45
# TEST: ./rwsiteinfo --no-title --no-final-delimiter --no-columns --fields=class,type --site-config-file ./tests/rwsiteinfo-site.conf

use strict;
use SiLKTests;

my $rwsiteinfo = check_silk_app('rwsiteinfo');

my $site_info = "$SiLKTests::srcdir/tests/rwsiteinfo-site.conf";
unless (-f $site_info) {
    skip_test("Did not find file '$site_info'");
}

my $cmd = "$rwsiteinfo --no-title --no-final-delimiter --no-columns --fields=class,type --site-config-file $SiLKTests::srcdir/tests/rwsiteinfo-site.conf";
my $md5 = "7d96db798427fc17e7fa27ff80993f45";

check_md5_output($md5, $cmd);
