#! /usr/bin/perl -w
# MD5: multiple
# TEST: multiple

#  Attempt to backup the original file to a non-existent directory;
#  should leave the new IPaggbag in the temp file.

# PSEUDO-TEST: mkdir /tmp/my-temp && cp ../../tests/aggbag2-v4.aggbag /tmp/my-temp/output && ./rwaggbagtool --modify-inplace --backup-path=/tmp/my-temp/x/y/z --output-path=/tmp/my-temp/output --add ../../tests/aggbag1-v4.aggbag /tmp/my-temp/output ; cmp ../../tests/aggbag2-v4.aggbag /tmp/my-temp/output ; rm -f /tmp/my-temp/output ; test 1 -eq `ls /tmp/my-temp | wc -l` ; rwaggbagcat /tmp/my-temp/*

use strict;
use SiLKTests;

my $NAME = $0;
$NAME =~ s,.*/,,;

my $rwaggbag = check_silk_app('rwaggbag');
my $rwaggbagbuild = check_silk_app('rwaggbagbuild');
my $rwaggbagcat = check_silk_app('rwaggbagcat');
my $rwaggbagtool = check_silk_app('rwaggbagtool');
my $rwfileinfo = check_silk_app('rwfileinfo');
my $tempdir = make_tempdir();
my %file;
$file{data} = get_data_or_exit77('data');
my %temp;
$temp{note} = make_tempname('note');
$temp{rwaggbag_ports_pro_rec} = make_tempname('rwaggbag_ports_pro_rec');

open NOTE, ">", $temp{note}
    or die "$NAME: Unable to open '$temp{note}' for write: $!\n";
print NOTE "NOTE: This is my notefile";
close NOTE
    or die "$NAME: Unable to close '$temp{note}' after write: $!\n";

my $cmd;
my $md5;

# Run rwaggbag and add an annotation
$cmd = ("$rwaggbag --note-add='NOTE: rwaggbag note'"
        ." --key=sport,dport,proto --counter=records"
        ." --output-path=$temp{rwaggbag_ports_pro_rec} $file{data}");
check_exit_status($cmd, 1)
    or die "$NAME: Error running rwaggbag\n";

# Verify the data created by rwaggbag
$cmd = "$rwaggbagcat $temp{rwaggbag_ports_pro_rec}";
$md5 = "4a8b3923f8436676975672c83c213096";
check_md5_output($md5, $cmd);

# Verify the annotations created by rwaggbag
$cmd = ("cat $temp{rwaggbag_ports_pro_rec}"
        ." | $rwfileinfo --fields=annotations -");
$md5 = "7372a64c3be58c1d0c4f7ef9aca86097";
check_md5_output($md5, $cmd);

# Run rwaggbagtool and check that notes pass-through
$cmd = ("$rwaggbagtool --add $temp{rwaggbag_ports_pro_rec}"
        ." | $rwfileinfo --fields=annotations -");
$md5 = "7372a64c3be58c1d0c4f7ef9aca86097";
check_md5_output($md5, $cmd);

# Run rwaggbagtool and strip incoming note
$cmd = ("$rwaggbagtool --note-strip --add $temp{rwaggbag_ports_pro_rec}"
        ." | $rwfileinfo --fields=annotations -");
$md5 = "05854cd1f0e5bbbae6121eb83e25bc4a";
check_md5_output($md5, $cmd);

# Run rwaggbagtool to strip incoming notes and add a note file
$cmd = ("$rwaggbagtool --note-strip --note-file-add=$temp{note}"
        ." --add $temp{rwaggbag_ports_pro_rec}"
        ." | $rwfileinfo --fields=annotations -");
$md5 = "f1c5f63d2d3e399d523d651b5f1a8a35";
check_md5_output($md5, $cmd);

# Run rwaggbagbuild and add a note; pipe into rwaggbagtool to add that
# stream with the rwaggbag output file, add a note, and write as an
# aggbag
$cmd = ("echo 655,655,65,65"
        ." | $rwaggbagbuild --note-add='NOTE: rwaggbagbuild note'"
        ." --fields=sport,dport,proto,records --column-separator=,"
        ." | $rwaggbagtool --note-add='NOTE: rwaggbagtool note'"
        ." --add - $temp{rwaggbag_ports_pro_rec}"
        ." | $rwfileinfo --fields=annotations -");
$md5 = "a15b5aef564062fcf3fbb785a93062d9";
check_md5_output($md5, $cmd);

# Repeat the above, but export as a bag
$cmd = ("echo 655,655,65,65"
        ." | $rwaggbagbuild --note-add='NOTE: rwaggbagbuild note'"
        ." --fields=sport,dport,proto,records --column-separator=,"
        ." | $rwaggbagtool --note-add='NOTE: rwaggbagtool note'"
        ." --to-bag=proto,records --add - $temp{rwaggbag_ports_pro_rec}"
        ." | $rwfileinfo --fields=annotations -");
$md5 = "a15b5aef564062fcf3fbb785a93062d9";
check_md5_output($md5, $cmd);

# Run rwaggbagbuild and add a note; pipe into rwaggbagtool that also adds a
# note and export as an IPset
$cmd = ("echo 10.10.10.10,10101010"
        ." | $rwaggbagbuild --note-add='NOTE: rwaggbagbuild note'"
        ." --fields=dIPv4,sum-bytes --column-separator=,"
        ." | $rwaggbagtool --note-add='NOTE: rwaggbagtool note'"
        ." --to-ipset=dIPv4 -"
        ." | $rwfileinfo --fields=annotations -");
$md5 = "d399b3b862b0a0fcca63b3cc9b36f2c9";
check_md5_output($md5, $cmd);

exit 0;
