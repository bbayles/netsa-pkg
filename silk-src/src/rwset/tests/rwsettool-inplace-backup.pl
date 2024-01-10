#! /usr/bin/perl -w
# MD5: fb63420d9993e09e4d02e1857a22a7f2
# TEST: cp ../../tests/set1-v4.set /tmp/rwsettool-inplace-backup-output && ./rwsettool --modify-inplace --backup-path=/tmp/rwsettool-inplace-backup-backup --output-path=/tmp/rwsettool-inplace-backup-output --union /tmp/rwsettool-inplace-backup-output ../../tests/set2-v4.set && cmp ../../tests/set1-v4.set /tmp/rwsettool-inplace-backup-backup && ./rwsetcat --cidr /tmp/rwsettool-inplace-backup-output

use strict;
use SiLKTests;

my $rwsettool = check_silk_app('rwsettool');
my $rwsetcat = check_silk_app('rwsetcat');
my %file;
$file{v4set1} = get_data_or_exit77('v4set1');
$file{v4set2} = get_data_or_exit77('v4set2');
my %temp;
$temp{output} = make_tempname('output');
$temp{backup} = make_tempname('backup');
my $cmd = "cp $file{v4set1} $temp{output} && $rwsettool --modify-inplace --backup-path=$temp{backup} --output-path=$temp{output} --union $temp{output} $file{v4set2} && cmp $file{v4set1} $temp{backup} && $rwsetcat --cidr $temp{output}";
my $md5 = "fb63420d9993e09e4d02e1857a22a7f2";

check_md5_output($md5, $cmd);
