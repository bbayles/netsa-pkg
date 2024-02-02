#! /usr/bin/perl -w
# MD5: multiple
# TEST: multiple

#  Attempt to union and use a non-existent file.  rwsettool should
#  remove the temp file before exiting

# PSEUDO-TEST: mkdir /tmp/my-temp && cp ../../tests/set1-v4.set /tmp/my-temp/output && ./rwsettool --modify-inplace --backup-path=/tmp/my-temp/backup --output-path=/tmp/my-temp/output --union /tmp/my-temp/output ../../tests/set2-v4.set /tmp/my-temp/nosuch ; cmp ../../tests/set1-v4.set /tmp/my-temp/output ; rm -f /tmp/my-temp/output ; test 0 -eq `ls /tmp/my-temp | wc -l`

use strict;
use SiLKTests;

my $rwsettool = check_silk_app('rwsettool');
my %file;
$file{v4set1} = get_data_or_exit77('v4set1');
$file{v4set2} = get_data_or_exit77('v4set2');
my $tempdir = make_tempdir();
my %temp;
$temp{output} = "$tempdir/v4set1";
$temp{nosuch} = "$tempdir/nosuch";
$temp{backup} = "$tempdir/backup";

my $cmd;

# cp $file{v4set1} $temp{output}
$cmd = "cp $file{v4set1} $temp{output}";
check_exit_status($cmd, 1)
    or die "ERROR: Failed to copy file\n";

# rwsettool --modify-iplace --backup-path=$temp{backup} \
#    --output-path=$temp{output} \
#    --union $temp{output} $file{v4set2} $temp{nosuch}
$cmd = ("$rwsettool --modify-inplace --backup-path=$temp{backup}"
        ." --output-path=$temp{output}"
        ." --union $temp{output} $file{v4set2} $temp{nosuch}");
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
if (0 != @files) {
    die join("\n\t",
             "ERROR: Expected 0 files in tempdir, found ".@files." file(s):",
             @files),
        "\n";
}

exit 0;
