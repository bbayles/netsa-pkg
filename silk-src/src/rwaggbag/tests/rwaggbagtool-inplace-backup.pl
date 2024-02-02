#! /usr/bin/perl -w
# MD5: 00a34db4f9cd99ee2ca9a65d0ed11a78
# TEST: ./rwaggbag --key=sport --counter=records --output-path=/tmp/rwaggbagtool-inplace-backup-sport_rec ../../tests/data.rwf && ./rwaggbag --key=sport --counter=sum-packets --output-path=/tmp/rwaggbagtool-inplace-backup-sport_pkts ../../tests/data.rwf && cp /tmp/rwaggbagtool-inplace-backup-sport_pkts /tmp/rwaggbagtool-inplace-backup-output && ./rwaggbagtool --modify-inplace --backup-path=/tmp/rwaggbagtool-inplace-backup-backup --output-path=/tmp/rwaggbagtool-inplace-backup-output --insert-field=records=0 --insert-field=sum-packets=0 --add /tmp/rwaggbagtool-inplace-backup-sport_rec /tmp/rwaggbagtool-inplace-backup-output && cmp /tmp/rwaggbagtool-inplace-backup-sport_pkts /tmp/rwaggbagtool-inplace-backup-backup && ./rwaggbagcat /tmp/rwaggbagtool-inplace-backup-output

use strict;
use SiLKTests;

use strict;
use SiLKTests;

my $NAME = $0;
$NAME =~ s,.+/,,;

my $rwaggbagtool = check_silk_app('rwaggbagtool');
my $rwaggbag = check_silk_app('rwaggbag');
my $rwaggbagcat = check_silk_app('rwaggbagcat');
my %file;
$file{data} = get_data_or_exit77('data');
my %temp;
$temp{sport_rec} = make_tempname('sport_rec');
$temp{sport_pkts} = make_tempname('sport_pkts');
$temp{backup} = make_tempname('backup');

my $cmd;
my $md5;

# Generate one data file
$cmd = ("$rwaggbag --key=sport --counter=records"
        ." --output-path=$temp{sport_rec} $file{data}");
check_exit_status($cmd, 1)
    or die "$NAME: Error running rwaggbag\n";
compute_md5_file(\$md5, $temp{sport_rec});

# Generate a second data file, to be overwritten
$cmd = ("$rwaggbag --key=sport --counter=sum-packets".
        " --output-path=$temp{sport_pkts} $file{data}");
check_exit_status($cmd, 1)
    or die "$NAME: Error running rwaggbag\n";
my $md5_sport_pkts;
compute_md5_file(\$md5_sport_pkts, $temp{sport_pkts});

# Run rwaggbagtool replacing the second file and backing it up
$cmd = ("$rwaggbagtool --modify-inplace --backup-path=$temp{backup}"
        ." --output-path=$temp{sport_pkts}"
        ." --add $temp{sport_rec} $temp{sport_pkts}"
        ." --insert-field=records=0 --insert-field=sum-packets=0");
check_exit_status($cmd, 1)
    or die "$NAME: Error running rwaggbagtool\n";

# sport_rec should be unchanged
check_md5_file($md5, $temp{sport_rec});

# former sport_pkts is now in backup
check_md5_file($md5_sport_pkts, $temp{backup});

# verify expected MD5 sum of the output
$cmd = "$rwaggbagcat $temp{sport_pkts}";
$md5 = "00a34db4f9cd99ee2ca9a65d0ed11a78";
check_md5_output($md5, $cmd);
