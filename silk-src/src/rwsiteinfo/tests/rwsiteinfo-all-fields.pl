#! /usr/bin/perl -w
# MD5: 0dfd3979bdb8b1f35c8b91ccfdb5e5a8
# TEST: ./rwsiteinfo --fields=class,type,flowtype,id-flowtype,sensor,id-sensor,describe-sensor,group,default-class,default-type,mark-defaults,class:list,type:list,flowtype:list,id-flowtype:list,sensor:list,id-sensor:list,group:list,default-class:list,default-type:list --site-config-file ./tests/rwsiteinfo-site.conf

use strict;
use SiLKTests;

my $rwsiteinfo = check_silk_app('rwsiteinfo');

my $site_info = "$SiLKTests::srcdir/tests/rwsiteinfo-site.conf";
unless (-f $site_info) {
    skip_test("Did not find file '$site_info'");
}

my $cmd = "$rwsiteinfo --fields=class,type,flowtype,id-flowtype,sensor,id-sensor,describe-sensor,group,default-class,default-type,mark-defaults,class:list,type:list,flowtype:list,id-flowtype:list,sensor:list,id-sensor:list,group:list,default-class:list,default-type:list --site-config-file $SiLKTests::srcdir/tests/rwsiteinfo-site.conf";
my $md5 = "0dfd3979bdb8b1f35c8b91ccfdb5e5a8";

check_md5_output($md5, $cmd);
