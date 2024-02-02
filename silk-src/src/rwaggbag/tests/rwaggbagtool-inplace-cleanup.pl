#! /usr/bin/perl -w
# MD5: multiple
# TEST: multiple

#  Attempt to add rwaggbag files with different keys.  all files
#  should be unchanged; rwaggbagtool should remove the temp file
#  before exiting

# PSEUDO-TEST: mkdir /tmp/my-temp && rwaggbag --key=sport,dport --counter=records --output-file=/tmp/my-temp/ports_rec ../../tests/data.rwf && rwaggbag --key=sipv4,dipv4 --counter=sum-packets --output-file=/tmp/my-temp/ips_pkts ../../tests/data.rwf && cp /tmp/my-temp/ports_rec /tmp/my-temp/save && ./rwaggbagtool --modify-inplace --backup-path=/tmp/my-temp/backup --output-path=/tmp/my-temp/ports_rec --add /tmp/my-temp/ips_pkts /tmp/my-temp/ports_rec ; cmp /tmp/my-temp/ports_rec /tmp/my-temp/save ; rm -f /tmp/my-temp/ips_pkts /tmp/my-temp/ports_rec ; test 0 -eq `ls /tmp/my-temp | wc -l`

use strict;
use SiLKTests;

my $NAME = $0;
$NAME =~ s,.*/,,;

my $rwaggbag = check_silk_app('rwaggbag');
my $rwaggbagtool = check_silk_app('rwaggbagtool');
my %file;
$file{data} = get_data_or_exit77('data');
my $tempdir = make_tempdir();
my %temp;
$temp{backup} = "$tempdir/backup";
$temp{rwaggbag_ips_pkts} = "$tempdir/rwaggbag_ips_pkts";
$temp{rwaggbag_ports_rec} = "$tempdir/rwaggbag_ports_rec";

my $cmd;
my $md5;

# Run rwaggbag on the ports
$cmd = "$rwaggbag --key=sport,dport --counter=records --output-path=$temp{rwaggbag_ports_rec} $file{data}";
check_exit_status($cmd, 1)
    or die "$NAME: Error running rwaggbag\n";

# Compute the MD5 of the result
compute_md5_file(\$md5, $temp{rwaggbag_ports_rec});

# Run rwaggbag on the IPs
$cmd = "$rwaggbag --key=sipv4,dipv4 --counter=sum-packets --output-path=$temp{rwaggbag_ips_pkts} $file{data}";
check_exit_status($cmd, 1)
    or die "$NAME: Error running rwaggbag\n";

# rwaggbagtool --modify-iplace --backup-path=$temp{backup} \
#    --output-path=$temp{rwaggbag_ports_rec} \
#    --add $temp{rwaggbag_ips_pkts} $file{rwaggbag_ports_rec}
$cmd = ("$rwaggbagtool --modify-inplace --backup-path=$temp{backup}"
        ." --output-path=$temp{rwaggbag_ports_rec}"
        ." --add $temp{rwaggbag_ips_pkts} $temp{rwaggbag_ports_rec}");
check_exit_status($cmd, 1)
    and die "ERROR: Command succeeded that should have failed\n";

# verify file we wanted to overwrite is unchanged
check_md5_file($md5, $temp{rwaggbag_ports_rec});

# remove the files we created
unlink($temp{rwaggbag_ips_pkts}, $temp{rwaggbag_ports_rec})
    or die "ERROR: Unable to remove temp files: $!\n";

my @files = grep { !m,/-silktests-$, } glob("$tempdir/*");
if (0 != @files) {
    die join("\n\t",
             "ERROR: Expected 0 files in tempdir, found ".@files." file(s):",
             @files),
        "\n";
}

exit 0;
