#! /usr/bin/perl -w
# MD5: multiple
# TEST: multiple

#  Attempt to backup the original file to a non-existent directory;
#  should leave the new IPset in the temp file.

# PSEUDO-TEST: mkdir /tmp/my-temp && cp ../../tests/set1-v4.set /tmp/my-temp/output && ./rwsettool --modify-inplace --backup-path=/tmp/my-temp/x/y/z --output-path=/tmp/my-temp/output --union /tmp/my-temp/output ../../tests/set2-v4.set ; cmp ../../tests/set1-v4.set /tmp/my-temp/output ; rm -f /tmp/my-temp/output ; test 1 -eq `ls /tmp/my-temp | wc -l` ; rwsetcat -cidr /tmp/my-temp/*

use strict;
use SiLKTests;

my $rwsettool = check_silk_app('rwsettool');
my $rwsetcat = check_silk_app('rwsetcat');
my %file;
$file{v4set1} = get_data_or_exit77('v4set1');
$file{v4set2} = get_data_or_exit77('v4set2');
my $tempdir = make_tempdir();
my %temp;
$temp{output} = "$tempdir/v4set1";

my $cmd;

# cp $file{v4set1} $temp{output}
$cmd = "cp $file{v4set1} $temp{output}";
check_exit_status($cmd, 1)
    or die "ERROR: Failed to copy file\n";

# rwsettool --modify-iplace --backup-path=$tempdir/x/y/z \
#    --output-path=$temp{output} \
#    --union $temp{output} $file{v4set2} $temp{nosuch}
$cmd = ("$rwsettool --modify-inplace --backup-path=$tempdir/x/y/z"
        ." --output-path=$temp{output}"
        ." --union $temp{output} $file{v4set2}");
check_exit_status($cmd, 1)
    and die "ERROR: Command succeeded that should have failed\n";

# verify copied file is unchanged using cmp
$cmd = "cmp $file{v4set1} $temp{output}";
check_exit_status($cmd, 1)
    or die "ERROR: Input file has changed\n";

# remove the copied file
unlink($temp{output})
    or die "ERROR: Unable to remove temp file: $!\n";

my @files = grep { !m,/-silktests-$, } glob("$tempdir/*");
if (1 != @files) {
    die join("\n\t",
             "ERROR: Expected 1 file in tempdir, found ".@files." files:",
             @files),
        "\n";
}

# verify temp file has expected MD5
$cmd = "$rwsetcat --cidr @files";
check_md5_output("fb63420d9993e09e4d02e1857a22a7f2", $cmd);

exit 0;
