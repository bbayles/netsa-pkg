#! /usr/bin/perl -w
# MD5: 59b22d8300990ab586fc71da1fd67484
# TEST: ./rwsiteinfo --fields=sensor:list,class:list,type:list --site-config-file ./tests/rwsiteinfo-site.conf

use strict;
use SiLKTests;

my $rwsiteinfo = check_silk_app('rwsiteinfo');

my $site_info = "$SiLKTests::srcdir/tests/rwsiteinfo-site.conf";
unless (-f $site_info) {
    skip_test("Did not find file '$site_info'");
}

my $cmd = "$rwsiteinfo --fields=sensor:list,class:list,type:list --site-config-file $SiLKTests::srcdir/tests/rwsiteinfo-site.conf";
my $md5 = "59b22d8300990ab586fc71da1fd67484";

check_md5_output($md5, $cmd);
