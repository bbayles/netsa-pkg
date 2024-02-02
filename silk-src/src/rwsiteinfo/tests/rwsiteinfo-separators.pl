#! /usr/bin/perl -w
# MD5: 02b5d36729137985121783e24bbfeb84
# TEST: ./rwsiteinfo --column-separator='+' --list-delimiter=';' --fields=class,type:list --site-config-file ./tests/rwsiteinfo-site.conf

use strict;
use SiLKTests;

my $rwsiteinfo = check_silk_app('rwsiteinfo');

my $site_info = "$SiLKTests::srcdir/tests/rwsiteinfo-site.conf";
unless (-f $site_info) {
    skip_test("Did not find file '$site_info'");
}

my $cmd = "$rwsiteinfo --column-separator='+' --list-delimiter=';' --fields=class,type:list --site-config-file $SiLKTests::srcdir/tests/rwsiteinfo-site.conf";
my $md5 = "02b5d36729137985121783e24bbfeb84";

check_md5_output($md5, $cmd);
