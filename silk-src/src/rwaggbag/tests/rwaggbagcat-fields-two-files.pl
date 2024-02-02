#! /usr/bin/perl -w
# MD5: 0dd45ccee2c1dbfbf9154081ded69e23
# TEST: ./rwaggbag --key=sport --counter=records --output-path=/tmp/rwaggbagcat-fields-two-files-sport_rec ../../tests/data.rwf && ./rwaggbag --key=dport --counter=records ../../tests/data.rwf | ./rwaggbagcat --fields=sport,dport,records --missing dport=0 --missing sport=0 /tmp/rwaggbagcat-fields-two-files-sport_rec -

use strict;
use SiLKTests;

my $rwaggbagcat = check_silk_app('rwaggbagcat');
my $rwaggbag = check_silk_app('rwaggbag');
my %file;
$file{data} = get_data_or_exit77('data');
my %temp;
$temp{sport_rec} = make_tempname('sport_rec');
my $cmd = "$rwaggbag --key=sport --counter=records --output-path=$temp{sport_rec} $file{data} && $rwaggbag --key=dport --counter=records $file{data} | $rwaggbagcat --fields=sport,dport,records --missing dport=0 --missing sport=0 $temp{sport_rec} -";
my $md5 = "0dd45ccee2c1dbfbf9154081ded69e23";

check_md5_output($md5, $cmd);
