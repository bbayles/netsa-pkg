#! /usr/bin/perl -w
# MD5: 0b98e7ba0e201bf2fa887ab2aeeba56f
# TEST: ./rwsiteinfo --delimited --fields=class,type,sensor --flowtype=@./tests/at-flowtype.txt --site-config-file ./tests/rwsiteinfo-site.conf

use strict;
use SiLKTests;

my $rwsiteinfo = check_silk_app('rwsiteinfo');

my $at_flowtype = "$SiLKTests::srcdir/tests/at-flowtype.txt";
unless (-f $at_flowtype) {
    skip_test("Did not find file '$at_flowtype'");
}
$at_flowtype =~ s/([\@\,])/\@$1/g;

my $site_info = "$SiLKTests::srcdir/tests/rwsiteinfo-site.conf";
unless (-f $site_info) {
    skip_test("Did not find file '$site_info'");
}

my $cmd = "$rwsiteinfo --delimited --fields=class,type,sensor --flowtype=\@$at_flowtype --site-config-file $SiLKTests::srcdir/tests/rwsiteinfo-site.conf";
my $md5 = "0b98e7ba0e201bf2fa887ab2aeeba56f";

check_md5_output($md5, $cmd);
