#! /usr/bin/perl -w
# MD5: 1c6d05e8d6641f996ec0d72e157db6a6
# TEST: ./rwsiteinfo --delimited --fields=class,type,sensor --class=@./tests/at-class.txt --site-config-file ./tests/rwsiteinfo-site.conf

use strict;
use SiLKTests;

my $rwsiteinfo = check_silk_app('rwsiteinfo');

my $at_class = "$SiLKTests::srcdir/tests/at-class.txt";
unless (-f $at_class) {
    skip_test("Did not find file '$at_class'");
}
$at_class =~ s/([\@\,])/\@$1/g;

my $site_info = "$SiLKTests::srcdir/tests/rwsiteinfo-site.conf";
unless (-f $site_info) {
    skip_test("Did not find file '$site_info'");
}

my $cmd = "$rwsiteinfo --delimited --fields=class,type,sensor --class=\@$at_class --site-config-file $SiLKTests::srcdir/tests/rwsiteinfo-site.conf";
my $md5 = "1c6d05e8d6641f996ec0d72e157db6a6";

check_md5_output($md5, $cmd);
