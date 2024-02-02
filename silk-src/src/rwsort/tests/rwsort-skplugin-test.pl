#! /usr/bin/perl -w
# MD5: 6d5de2000d6473006117de73bb698329
# TEST: ./rwsort --plugin=skplugin-test.so --fields=copy-bytes ../../tests/data.rwf | ../rwstats/rwuniq --plugin=skplugin-test.so --ipv6-policy=ignore --fields=copy-bytes --values=bytes,packets,records --presorted-input

use strict;
use SiLKTests;


#   On macOS, security settings often cause this test to fail.
#
#   It never seems to work on the files if they have not been
#   installed.
#
#   If they have been installed, then setting the RWSORT and RWUNIQ
#   environment variables to the installation location may allow the
#   test to succeed.
#
#   The work-arounds to make the test work seem to change with
#   different releases.  For example, at one point running rwsort by
#   itself produced an error but using "cat /dev/null |" in front of
#   rwsort allowed it to work.
#
#   Now (macOS Ventura) it appears that things work if they are
#   executed from within Perl but not when Perl runs /bin/sh to run
#   the command.
#
#   *SHRUG*


my $rwsort = check_silk_app('rwsort');
my $rwuniq = check_silk_app('rwuniq');
my %file;
$file{data} = get_data_or_exit77('data');
my %temp;
$temp{sorted} = make_tempname('sorted');
add_plugin_dirs('/src/plugins');

skip_test('Cannot load skplugin-test.so plugin')
    unless check_app_switch("$rwsort --plugin=skplugin-test.so", 'fields', qr/copy-bytes/);

my ($cmd, $md5);

$cmd = "$rwsort --plugin=skplugin-test.so --fields=copy-bytes --output-path=$temp{sorted} $file{data}";
$md5 = "d41d8cd98f00b204e9800998ecf8427e";  # MD5 of empty string
check_md5_output($md5, $cmd);

$cmd = "$rwuniq --plugin=skplugin-test.so --ipv6-policy=ignore --fields=copy-bytes --values=bytes,packets,records --presorted-input $temp{sorted}";
$md5 = "6d5de2000d6473006117de73bb698329";
check_md5_output($md5, $cmd);
