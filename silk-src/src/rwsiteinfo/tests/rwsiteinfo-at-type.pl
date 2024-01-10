#! /usr/bin/perl -w
# MD5: bd8df452c181a92376144e296fe87239
# TEST: ./rwsiteinfo --delimited --fields=class,type,sensor --type=@./tests/at-type.txt --site-config-file ./tests/rwsiteinfo-site.conf

use strict;
use SiLKTests;

my $rwsiteinfo = check_silk_app('rwsiteinfo');

my $at_type = "$SiLKTests::srcdir/tests/at-type.txt";
unless (-f $at_type) {
    skip_test("Did not find file '$at_type'");
}
$at_type =~ s/([\@\,])/\@$1/g;

my $site_info = "$SiLKTests::srcdir/tests/rwsiteinfo-site.conf";
unless (-f $site_info) {
    skip_test("Did not find file '$site_info'");
}

my $cmd = "$rwsiteinfo --delimited --fields=class,type,sensor --type=\@$at_type --site-config-file $SiLKTests::srcdir/tests/rwsiteinfo-site.conf";
my $md5 = "bd8df452c181a92376144e296fe87239";

check_md5_output($md5, $cmd);
