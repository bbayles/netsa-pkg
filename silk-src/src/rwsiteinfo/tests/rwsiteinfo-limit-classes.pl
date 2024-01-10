#! /usr/bin/perl -w
# MD5: f1a32d9e6e36c721843802ad6fd8501b
# TEST: ./rwsiteinfo --output-path=stdout --fields=sensor,class --classes=@,bar-class --site-config-file ./tests/rwsiteinfo-site.conf

use strict;
use SiLKTests;

my $rwsiteinfo = check_silk_app('rwsiteinfo');

my $site_info = "$SiLKTests::srcdir/tests/rwsiteinfo-site.conf";
unless (-f $site_info) {
    skip_test("Did not find file '$site_info'");
}

my $cmd = "$rwsiteinfo --output-path=stdout --fields=sensor,class --classes=@,bar-class --site-config-file $SiLKTests::srcdir/tests/rwsiteinfo-site.conf";
my $md5 = "f1a32d9e6e36c721843802ad6fd8501b";

check_md5_output($md5, $cmd);
