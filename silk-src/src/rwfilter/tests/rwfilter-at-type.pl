#! /usr/bin/perl -w
# MD5: 43488186ca47b3fb02b383a0fe63a19c
# TEST: ./rwfilter --type=@/tmp/type.txt --pass=stdout ../../tests/data.rwf | ../rwcat/rwcat --compression-method=none --byte-order=little --ipv4-output

use strict;
use SiLKTests;

my $rwfilter = check_silk_app('rwfilter');
my $rwcat = check_silk_app('rwcat');
my %file;
$file{data} = get_data_or_exit77('data');


# create our tempdir
my $tmpdir = make_tempdir();

# the file of types
my $type_file = "$tmpdir/type.txt";
my $type_text = "    in    ";

make_config_file($type_file, \$type_text);
$type_file =~ s/([\@\,])/\@$1/g;

my $cmd = "$rwfilter --type=\@$type_file --pass=stdout $file{data} | $rwcat --compression-method=none --byte-order=little --ipv4-output";
my $md5 = "43488186ca47b3fb02b383a0fe63a19c";

check_md5_output($md5, $cmd);
