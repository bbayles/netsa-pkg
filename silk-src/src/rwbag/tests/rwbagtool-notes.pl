#! /usr/bin/perl -w
# MD5: multiple
# TEST: printf 'NOTE: This is my notefile' > /tmp/note ; rwbag --note-add='NOTE: rwbag note' --proto-bytes=/tmp/rwbag_pro_byt data.rwf ; rwbagcat /tmp/rwbag_pro_byt ; cat /tmp/rwbag_pro_byt | rwfileinfo --fields=annotations - ; rwbagtool --add /tmp/rwbag_pro_byt | rwfileinfo --fields=annotations - ; rwbagtool --note-strip --add /tmp/rwbag_pro_byt | rwfileinfo --fields=annotations - ; rwbagtool --note-strip --note-file-add=/tmp/note --add /tmp/rwbag_pro_byt | rwfileinfo --fields=annotations - ; echo 443,344 | rwbagbuild --note-add='NOTE: rwbagbuild note' --bag-input=- --delimiter=, --key-type=sport --counter-type=packets | rwbagtool --note-add='NOTE: rwbagtool note' --add - /tmp/rwbag_pro_byt | rwfileinfo --fields=annotations - ; echo 10.10.10.10,10101010 | rwbagbuild --note-add='NOTE: rwbagbuild note' --bag-input=- --delimiter=, --key-type=dIPv4 --counter-type=bytes | rwbagtool --note-add='NOTE: rwbagtool note' --coverset - | rwfileinfo --fields=annotations -

#   Verifies that notes (annotations) are handled correctly

use strict;
use SiLKTests;

my $NAME = $0;
$NAME =~ s,.*/,,;

my $rwbag = check_silk_app('rwbag');
my $rwbagbuild = check_silk_app('rwbagbuild');
my $rwbagcat = check_silk_app('rwbagcat');
my $rwbagtool = check_silk_app('rwbagtool');
my $rwfileinfo = check_silk_app('rwfileinfo');
my $tempdir = make_tempdir();
my %file;
$file{data} = get_data_or_exit77('data');
my %temp;
$temp{note} = make_tempname('note');
$temp{rwbag_pro_byt} = make_tempname('rwbag_pro_byt');

open NOTE, ">", $temp{note}
    or die "$NAME: Unable to open '$temp{note}' for write: $!\n";
print NOTE "NOTE: This is my notefile";
close NOTE
    or die "$NAME: Unable to close '$temp{note}' after write: $!\n";

my $cmd;
my $md5;

# Run rwbag and add an annotation
$cmd = "$rwbag --note-add='NOTE: rwbag note' --proto-bytes=$temp{rwbag_pro_byt} $file{data}";
check_exit_status($cmd, 1)
    or die "$NAME: Error running rwbag\n";

# Verify the data created by rwbag
$cmd = "$rwbagcat $temp{rwbag_pro_byt}";
$md5 = "fd067d4f1085ee8ceba7780344472ced";
check_md5_output($md5, $cmd);

# Verify the annotations created by rwbag
$cmd = "cat $temp{rwbag_pro_byt} | $rwfileinfo --fields=annotations -";
$md5 = "ef9ba5f9dfc934983796b05a35fcc974";
check_md5_output($md5, $cmd);

# Run rwbagtool and check that notes pass-through
$cmd = "$rwbagtool --add $temp{rwbag_pro_byt} | $rwfileinfo --fields=annotations -";
$md5 = "ef9ba5f9dfc934983796b05a35fcc974";
check_md5_output($md5, $cmd);

# Run rwbagtool and strip incoming note
$cmd = "$rwbagtool --note-strip --add $temp{rwbag_pro_byt} | $rwfileinfo --fields=annotations -";
$md5 = "05854cd1f0e5bbbae6121eb83e25bc4a";
check_md5_output($md5, $cmd);

# Run rwbagtool to strip incoming notes and add a note file
$cmd = "$rwbagtool --note-strip --note-file-add=$temp{note} --add $temp{rwbag_pro_byt} | $rwfileinfo --fields=annotations -";
$md5 = "f1c5f63d2d3e399d523d651b5f1a8a35";
check_md5_output($md5, $cmd);

# Run rwbagbuild and add a note; pipe into rwbagtool to add that
# stream with the rwbag output file, add a note, and write as a bag
$cmd = "echo 443,344 | $rwbagbuild --note-add='NOTE: rwbagbuild note' --bag-input=- --delimiter=, --key-type=sport --counter-type=packets | $rwbagtool --note-add='NOTE: rwbagtool note' --add - $temp{rwbag_pro_byt} | $rwfileinfo --fields=annotations -";
$md5 = "c4c3393dc552d71c8d86dc6b756f25d2";
check_md5_output($md5, $cmd);

# Run rwbagbuild and add a note; pipe into rwbagtool that also adds a
# note and export as an IPset
$cmd = "echo 10.10.10.10,10101010 | $rwbagbuild --note-add='NOTE: rwbagbuild note' --bag-input=- --delimiter=, --key-type=dIPv4 --counter-type=bytes | $rwbagtool --note-add='NOTE: rwbagtool note' --coverset - | $rwfileinfo --fields=annotations -";
$md5 = "b3c627892bdc8bea2a42f2fb4e5e634b";
check_md5_output($md5, $cmd);

exit 0;
