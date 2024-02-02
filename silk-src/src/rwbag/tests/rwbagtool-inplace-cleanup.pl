#! /usr/bin/perl -w
# MD5: multiple
# TEST: multiple

#  Attempt to add and use a non-existent file.  rwbagtool should
#  remove the temp file before exiting

# PSEUDO-TEST: mkdir /tmp/my-temp && cp ../../tests/bag2-v4.bag /tmp/my-temp/output && ./rwbagtool --modify-inplace --backup-path=/tmp/my-temp/backup --output-path=/tmp/my-temp/output --add ../../tests/bag1-v4.bag /tmp/my-temp/output /tmp/my-temp/nosuch ; cmp ../../tests/bag2-v4.bag /tmp/my-temp/output ; rm -f /tmp/my-temp/output ; test 0 -eq `ls /tmp/my-temp | wc -l`

use strict;
use SiLKTests;

my $rwbagtool = check_silk_app('rwbagtool');
my %file;
$file{v4bag1} = get_data_or_exit77('v4bag1');
$file{v4bag2} = get_data_or_exit77('v4bag2');
my $tempdir = make_tempdir();
my %temp;
$temp{output} = "$tempdir/v4bag2";
$temp{nosuch} = "$tempdir/nosuch";
$temp{backup} = "$tempdir/backup";

my $cmd;

# cp $file{v4bag2} $temp{output}
$cmd = "cp $file{v4bag2} $temp{output}";
check_exit_status($cmd, 1)
    or die "ERROR: Failed to copy file\n";

# rwbagtool --modify-iplace --backup-path=$temp{backup} \
#    --output-path=$temp{output} \
#    --add $temp{output} $file{v4bag2} $temp{nosuch}
$cmd = ("$rwbagtool --modify-inplace --backup-path=$temp{backup}"
        ." --output-path=$temp{output}"
        ." --add $temp{output} $file{v4bag2} $temp{nosuch}");
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
if (0 != @files) {
    die join("\n\t",
             "ERROR: Expected 0 files in tempdir, found ".@files." file(s):",
             @files),
        "\n";
}

exit 0;
