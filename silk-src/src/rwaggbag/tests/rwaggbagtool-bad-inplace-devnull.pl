#! /usr/bin/perl -w
# STATUS: ERR
# TEST: ./rwaggbag --key=sport --counter=records --output-path=/tmp/rwaggbagtool-bad-inplace-devnull-sport_rec ../../tests/data.rwf && ./rwaggbagtool --modify-inplace --output-path=/dev/null --add /tmp/rwaggbagtool-bad-inplace-devnull-sport_rec >/dev/null

use strict;
use SiLKTests;

my $rwaggbagtool = check_silk_app('rwaggbagtool');
my $rwaggbag = check_silk_app('rwaggbag');
my %file;
$file{data} = get_data_or_exit77('data');
my %temp;
$temp{sport_rec} = make_tempname('sport_rec');
my $cmd = "$rwaggbag --key=sport --counter=records --output-path=$temp{sport_rec} $file{data} && $rwaggbagtool --modify-inplace --output-path=/dev/null --add $temp{sport_rec} >/dev/null";

exit (check_exit_status($cmd) ? 1 : 0);
