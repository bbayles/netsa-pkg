#! /usr/bin/perl -w
# MD5: 43eac40f7d7fa2f49c3fced566c139dc
# TEST: ./rwsiteinfo --fields=flowtype,class --flowtypes=all/type1,bar-class/all,foo-class/type5 --site-config-file ./tests/rwsiteinfo-site.conf

use strict;
use SiLKTests;

my $rwsiteinfo = check_silk_app('rwsiteinfo');

my $site_info = "$SiLKTests::srcdir/tests/rwsiteinfo-site.conf";
unless (-f $site_info) {
    skip_test("Did not find file '$site_info'");
}

my $cmd = "$rwsiteinfo --fields=flowtype,class --flowtypes=all/type1,bar-class/all,foo-class/type5 --site-config-file $SiLKTests::srcdir/tests/rwsiteinfo-site.conf";
my $md5 = "43eac40f7d7fa2f49c3fced566c139dc";

check_md5_output($md5, $cmd);
