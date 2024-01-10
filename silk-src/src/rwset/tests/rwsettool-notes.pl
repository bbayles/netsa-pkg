#! /usr/bin/perl -w
# MD5: multiple
# TEST: printf 'NOTE: This is my notefile' > /tmp/note ; rwset --note-add='NOTE: rwset note' --sip-file=/tmp/rwset-sip data.rwf ; rwsetcat --cidr-blocks=0 /tmp/rwset-sip ; cat /tmp/rwset-sip | rwfileinfo --fields=annotations - ; rwsettool --union /tmp/rwset-sip | rwfileinfo --fields=annotations - ; rwsettool --note-strip --union /tmp/rwset-sip | rwfileinfo --fields=annotations - ; rwsettool --note-strip --note-file-add=/tmp/note --union /tmp/rwset-sip | rwfileinfo --fields=annotations - ; echo 10.10.10.10 | rwsetbuild --note-add='NOTE: rwsetbuild note' | rwsettool --note-add='NOTE: rwsettool note' --union - /tmp/rwset-sip | rwfileinfo --fields=annotations -

#   Verifies that notes (annotations) are handled correctly

use strict;
use SiLKTests;

my $NAME = $0;
$NAME =~ s,.*/,,;

my $rwset = check_silk_app('rwset');
my $rwsetbuild = check_silk_app('rwsetbuild');
my $rwsetcat = check_silk_app('rwsetcat');
my $rwsettool = check_silk_app('rwsettool');
my $rwfileinfo = check_silk_app('rwfileinfo');
my $tempdir = make_tempdir();
my %file;
$file{data} = get_data_or_exit77('data');
my %temp;
$temp{note} = make_tempname('note');
$temp{rwset_sip} = make_tempname('rwset_sip');

open NOTE, ">", $temp{note}
    or die "$NAME: Unable to open '$temp{note}' for write: $!\n";
print NOTE "NOTE: This is my notefile";
close NOTE
    or die "$NAME: Unable to close '$temp{note}' after write: $!\n";

my $cmd;
my $md5;

# Run rwset and add an annotation
$cmd = ("$rwset --note-add='NOTE: rwset note'"
        ." --sip-file=$temp{rwset_sip} $file{data}");
check_exit_status($cmd, 1)
    or die "$NAME: Error running rwset\n";

# Verify the data created by rwset
$cmd = "$rwsetcat --cidr-blocks=0 $temp{rwset_sip}";
$md5 = "3677d3da40803d98298314b69fadf06a";
check_md5_output($md5, $cmd);

# Verify the annotations created by rwset
$cmd = "cat $temp{rwset_sip} | $rwfileinfo --fields=annotations -";
$md5 = "77ad43ac1e0b1f83605737c86e416fba";
check_md5_output($md5, $cmd);

# Run rwsettool and check that notes pass-through
$cmd = ("$rwsettool --union $temp{rwset_sip}"
        ." | $rwfileinfo --fields=annotations -");
$md5 = "77ad43ac1e0b1f83605737c86e416fba";
check_md5_output($md5, $cmd);

# Run rwsettool and strip incoming note
$cmd = ("$rwsettool --note-strip --union $temp{rwset_sip}"
        ." | $rwfileinfo --fields=annotations -");
$md5 = "05854cd1f0e5bbbae6121eb83e25bc4a";
check_md5_output($md5, $cmd);

# Run rwsettool to strip incoming notes and add a note file
$cmd = ("$rwsettool --note-strip --note-file-add=$temp{note}"
        ." --union $temp{rwset_sip}"
        ." | $rwfileinfo --fields=annotations -");
$md5 = "f1c5f63d2d3e399d523d651b5f1a8a35";
check_md5_output($md5, $cmd);

# Run rwsetbuild and add a note; run rwsettool to add that file and
# the rwset output file and to add its own note
$cmd = ("echo 10.10.10.10"
        ." | $rwsetbuild --note-add='NOTE: rwsetbuild note'"
        ." | $rwsettool --note-add='NOTE: rwsettool note'"
        ."   --union - $temp{rwset_sip}"
        ." | $rwfileinfo --fields=annotations -");
$md5 = "d42545400023b73dcd50a0a26edba2d9";
check_md5_output($md5, $cmd);

exit 0;
