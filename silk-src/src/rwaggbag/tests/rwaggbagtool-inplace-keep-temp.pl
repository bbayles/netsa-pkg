#! /usr/bin/perl -w
# MD5: multiple
# TEST: multiple

#  Attempt to backup the original file to a non-existent directory;
#  should leave the files unchanged and the new AggBag in the temp
#  file.

# PSEUDO-TEST: mkdir /tmp/my-temp && rwaggbag --key=sport,dport --counter=records --output-file=/tmp/my-temp/ports_rec ../../tests/data.rwf && rwaggbag --key=sport,dport --counter=sum-packets --output-file=/tmp/my-temp/ports_pkts ../../tests/data.rwf && cp /tmp/my-temp/ports_rec /tmp/my-temp/save && ./rwaggbagtool --modify-inplace --backup-path=/tmp/my-temp/x/y/z --output-path=/tmp/my-temp/ports_rec --insert-field=records=0 --insert-field=sum-packets=0 --add /tmp/my-temp/ports_pkts /tmp/my-temp/ports_rec ; cmp /tmp/my-temp/ports_rec /tmp/my-temp/save ; rm -f /tmp/my-temp/ports_pkts /tmp/my-temp/ports_rec ; test 1 -eq `ls /tmp/my-temp | wc -l` ; rwbagcat /tmp/my-temp/*

use strict;
use SiLKTests;
my $NAME = $0;
$NAME =~ s,.*/,,;

my $rwaggbag = check_silk_app('rwaggbag');
my $rwaggbagcat = check_silk_app('rwaggbagcat');
my $rwaggbagtool = check_silk_app('rwaggbagtool');
my %file;
$file{data} = get_data_or_exit77('data');
my $tempdir = make_tempdir();
my %temp;
$temp{rwaggbag_ports_pkts} = "$tempdir/rwaggbag_ports_pkts";
$temp{rwaggbag_ports_rec} = "$tempdir/rwaggbag_ports_rec";

my $cmd;
my $md5;

# Run rwaggbag on the ports and count records
$cmd = "$rwaggbag --key=sport,dport --counter=records --output-path=$temp{rwaggbag_ports_rec} $file{data}";
check_exit_status($cmd, 1)
    or die "$NAME: Error running rwaggbag\n";

# Compute the MD5 of the result
compute_md5_file(\$md5, $temp{rwaggbag_ports_rec});

# Run rwaggbag on the ports and sum the packets
$cmd = "$rwaggbag --key=sport,dport --counter=sum-packets --output-path=$temp{rwaggbag_ports_pkts} $file{data}";
check_exit_status($cmd, 1)
    or die "$NAME: Error running rwaggbag\n";

# Run rwaggbagtool to add the files using --modify-inplace and --backup-path
$cmd = ("$rwaggbagtool --modify-inplace --backup-path=$tempdir/x/y/z"
        ." --output-path=$temp{rwaggbag_ports_rec}"
        ." --insert-field=records=0 --insert-field=sum-packets=0"
        ." --add $temp{rwaggbag_ports_pkts} $temp{rwaggbag_ports_rec}");
check_exit_status($cmd, 1)
    and die "ERROR: Command succeeded that should have failed\n";

# Verify file we wanted to overwrite is unchanged
check_md5_file($md5, $temp{rwaggbag_ports_rec});

# Remove the files we created
unlink($temp{rwaggbag_ports_pkts}, $temp{rwaggbag_ports_rec})
    or die "ERROR: Unable to remove temp files: $!\n";

# The temp-file should be the only file left
my @files = grep { !m,/-silktests-$, } glob("$tempdir/*");
if (1 != @files) {
    die join("\n\t",
             "ERROR: Expected 1 file in tempdir, found ".@files." files:",
             @files),
        "\n";
}

# verify temp file has expected MD5
$cmd = "$rwaggbagcat @files";
$md5 = "b03190d032bbb4f90b18d354906bd2e3";
check_md5_output($md5, $cmd);

exit 0;
