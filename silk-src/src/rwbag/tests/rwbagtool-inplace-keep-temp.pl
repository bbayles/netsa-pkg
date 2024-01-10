#! /usr/bin/perl -w
# MD5: multiple
# TEST: multiple

#  Attempt to backup the original file to a non-existent directory;
#  should leave the new IPbag in the temp file.

# PSEUDO-TEST: mkdir /tmp/my-temp && cp ../../tests/bag2-v4.bag /tmp/my-temp/output && ./rwbagtool --modify-inplace --backup-path=/tmp/my-temp/x/y/z --output-path=/tmp/my-temp/output --add ../../tests/bag1-v4.bag /tmp/my-temp/output ; cmp ../../tests/bag2-v4.bag /tmp/my-temp/output ; rm -f /tmp/my-temp/output ; test 1 -eq `ls /tmp/my-temp | wc -l` ; rwbagcat /tmp/my-temp/*

use strict;
use SiLKTests;

my $rwbagtool = check_silk_app('rwbagtool');
my $rwbagcat = check_silk_app('rwbagcat');
my %file;
$file{v4bag1} = get_data_or_exit77('v4bag1');
$file{v4bag2} = get_data_or_exit77('v4bag2');
my $tempdir = make_tempdir();
my %temp;
$temp{output} = "$tempdir/v4bag1";

my $cmd;

# cp $file{v4bag2} $temp{output}
$cmd = "cp $file{v4bag2} $temp{output}";
check_exit_status($cmd, 1)
    or die "ERROR: Failed to copy file\n";

# rwbagtool --modify-iplace --backup-path=$tempdir/x/y/z \
#    --output-path=$temp{output} \
#    --add $file{v4bag1} $temp{output}
$cmd = ("$rwbagtool --modify-inplace --backup-path=$tempdir/x/y/z"
        ." --output-path=$temp{output}"
        ." --add $file{v4bag1} $temp{output}");
check_exit_status($cmd, 1)
    and die "ERROR: Command succeeded that should have failed\n";

# verify copied file is unchanged using cmp
$cmd = "cmp $file{v4bag2} $temp{output}";
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
$cmd = "$rwbagcat @files";
check_md5_output("e4bfe9a5a80b369c2ce291bad424c49a", $cmd);

exit 0;
