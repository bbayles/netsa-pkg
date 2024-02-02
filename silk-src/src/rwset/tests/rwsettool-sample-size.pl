#! /usr/bin/perl -w
# MD5: multiple
# TEST: multiple

use strict;
use SiLKTests;

# find the apps we need.  this will exit 77 if they're not available
my $rwset = check_silk_app('rwset');
my $rwsetcat = check_silk_app('rwsetcat');
my $rwsettool = check_silk_app('rwsettool');

# find the data files we use as sources, or exit 77
my %file;
$file{data} = get_data_or_exit77('data');

my %temp;
$temp{sipset} = make_tempname('sipset');
$temp{sampleset} = make_tempname('sampleset');

# result of running MD5 on /dev/null
my $empty_md5 = 'd41d8cd98f00b204e9800998ecf8427e';

my ($cmd, $md5);

# create source set from the data.rwf
$cmd = "$rwset --sip-file=$temp{sipset} $file{data}";
check_md5_output($empty_md5, $cmd);

# create sample set
$cmd = ("$rwsettool --sample --size=2000 $temp{sipset}"
        ." --compression=none --invocation-strip --record-version=4"
        ." --output-path=$temp{sampleset}");
check_md5_output($empty_md5, $cmd);

# Intersection of sample set with source set should be sample set
compute_md5_file(\$md5, $temp{sampleset});

$cmd = ("$rwsettool --intersect $temp{sipset} $temp{sampleset}"
        ." --compression=none --invocation-strip --record-version=4");
check_md5_output($md5, $cmd);

# sample larger than number of IPs in the set should return the same
# set
$cmd = ("$rwsettool --sample --size=3000 $temp{sampleset}"
        ." --compression=none --invocation-strip --record-version=4");
check_md5_output($md5, $cmd);

# count IPs in the set
$cmd = "echo 2000";
compute_md5(\$md5, $cmd);

$cmd = "$rwsetcat --count $temp{sampleset}";
check_md5_output($md5, $cmd);

# sample of two non-overlapping IPsets should return two-times the
# sample size (when each IPset is large enough)
$cmd = "echo 200";
compute_md5(\$md5, $cmd);

$cmd = ("$rwsettool --difference $temp{sipset} $temp{sampleset}"
        ." | $rwsettool --sample --size=100 - $temp{sampleset}"
        ." | $rwsetcat --count");
check_md5_output($md5, $cmd);
