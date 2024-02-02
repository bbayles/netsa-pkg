#! /usr/bin/perl -w
# ERR_MD5: d41d8cd98f00b204e9800998ecf8427e
# TEST: ./rwsiteinfo --delimited --fields=class,type,sensor --sensors=@./tests/at-no-recurse.txt --site-config-file ./tests/rwsiteinfo-site.conf

use strict;
use SiLKTests;

my $rwsiteinfo = check_silk_app('rwsiteinfo');

my $at_no_recurse = "$SiLKTests::srcdir/tests/at-no-recurse.txt";
unless (-f $at_no_recurse) {
    skip_test("Did not find file '$at_no_recurse'");
}
$at_no_recurse =~ s/([\@\,])/\@$1/g;

my $site_info = "$SiLKTests::srcdir/tests/rwsiteinfo-site.conf";
unless (-f $site_info) {
    skip_test("Did not find file '$site_info'");
}

my $cmd = "$rwsiteinfo --delimited --fields=class,type,sensor --sensors=\@$at_no_recurse --site-config-file $SiLKTests::srcdir/tests/rwsiteinfo-site.conf";
my $md5 = "d41d8cd98f00b204e9800998ecf8427e";

check_md5_output($md5, $cmd, 1);
