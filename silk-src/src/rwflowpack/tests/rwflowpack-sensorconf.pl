#! /usr/bin/perl -w
# ERR_MD5: varies
# TEST: ./rwflowpack ----sensor-conf=sk-teststmp-sensor.conf --verify-sensor 2>&1"

use strict;
use SiLKTests;

my $NAME = $0;
$NAME =~ s,.*/,,;

my %file;
$file{v4set1} = get_data_or_exit77('v4set1');
$file{v4set2} = get_data_or_exit77('v4set2');

if ($SiLKTests::SK_ENABLE_IPV6) {
    $file{v6set1} = get_data_or_exit77('v6set1');
    $file{v6set2} = get_data_or_exit77('v6set2');
}
else {
    $file{v6set1} = $file{v4set1};
    $file{v6set2} = $file{v4set2};
}

my $rwflowpack = check_silk_app('rwflowpack');

# set the environment variables required for rwflowpack to find its
# packing logic plug-in
add_plugin_dirs('/site/twoway');

# Skip this test if we cannot load the packing logic
check_exit_status("$rwflowpack --sensor-conf=$srcdir/tests/sensor77.conf"
                  ." --verify-sensor-conf")
    or skip_test("Cannot load packing logic");

# MD5 of /dev/null (no output)
my $md5_no_output = "d41d8cd98f00b204e9800998ecf8427e";

# create our tempdir
my $tmpdir = make_tempdir();

# move IPset files into tempdir
for my $f (keys %file) {
    my $basename = $file{$f};
    $basename =~ s,.*/,,;
    my $dest = "$tmpdir/$basename";
    unless (-f $dest) {
        check_md5_output($md5_no_output, "cp $file{$f} $dest");
    }
    $file{$f} = $dest;
}


# list of probe types
my @probe_types = qw(netflow-v5 ipfix silk netflow-v9 sflow);

# valid ways to get data into SiLK, though not every probe type
# supports each of these sources
my @sources_valid = (
    ["poll-directory /tmp/incoming-nf"],

    ["protocol udp", "listen-on-port 9900"],
    ["protocol udp", "listen-on-port 9901",
     "listen-as-host 127.0.0.1"],
    ["protocol udp", "listen-on-port 9902",
     "accept-from-host 127.0.0.1"],
    ["protocol udp", "listen-on-port 9903",
     "listen-as-host 127.0.0.1", "accept-from-host 127.0.0.1 127.0.0.2"],

    ["protocol tcp", "listen-on-port 9900"],
    ["protocol tcp", "listen-on-port 9901",
     "listen-as-host 127.0.0.1"],
    ["protocol tcp", "listen-on-port 9902",
     "accept-from-host 127.0.0.1"],
    ["protocol tcp", "listen-on-port 9903",
     "listen-as-host 127.0.0.1", "accept-from-host 127.0.0.1"],

    ["read-from-file /tmp/incoming-nf"],
    );

# the following are invalid/unsupported sources
my @sources_bad = (
    # no current probes support this
    ["listen-on-unix-socket /tmp/incoming-nf"],
    # missing protocol, port, or both
    ["listen-on-port 9900"],
    ["protocol udp", "listen-as-host 127.0.0.1"],
    ["protocol udp"],
    ["listen-as-host 127.0.0.1"],
    # cannot have list of ports
    ["protocol udp", "listen-on-port 9900,9901"],
    # cannot have host as part of port
    ["protocol udp", "listen-on-port 127.0.0.1:9900"],
    # cannot have port as part of host
    ["protocol udp", "listen-as-host 127.0.0.1:9900"],
    ["protocol udp", "listen-on-port 9900"],
    # cannot have list as argument to listen-as-host
#    ["protocol udp", "listen-on-port 9900", "listen-as-host 10.0.0.1 10.0.0.2"],
    # invalid accept-from-host
    ["protocol udp", "listen-on-port 9900", "accept-from-host 127.0.0.1:8888"],
    ["protocol udp", "listen-on-port 9900", "accept-from-host 8888"],
    # multiple sources
    ["protocol udp", "listen-on-port 9900", "poll-directory /tmp/incoming-nf"],
    ["protocol udp", "listen-on-port 9900", "read-from-file /tmp/incoming-nf"],
    ["poll-directory /tmp/incoming-nf", "read-from-file /tmp/incoming-nf"],
    ["poll-directory /tmp/incoming-nf", "accept-from-host 127.0.0.1"],
    ["accept-from-host 127.0.0.1", "read-from-file /tmp/incoming-nf"],
    # must have unique poll-directory
    ["poll-directory /tmp/duplicate-polldir"],
    ["poll-directory /tmp/duplicate-polldir"],
    # must have unique (listen-on-port, listen-as-host, accept-from-host)
    ["protocol udp", "listen-on-port 9901"],
    ["protocol udp", "listen-on-port 9901"],
    ["protocol udp", "listen-on-port 9902", "listen-as-host 127.0.0.1"],
    ["protocol udp", "listen-on-port 9902", "listen-as-host 127.0.0.1"],
    ["protocol udp", "listen-on-port 9903", "listen-as-host 127.0.0.1"],
    ["protocol udp", "listen-on-port 9903", "listen-as-host localhost"],
    ["protocol udp", "listen-on-port 9904", "accept-from-host 127.0.0.1"],
    ["protocol udp", "listen-on-port 9904", "accept-from-host 127.0.0.1"],
    ["protocol udp", "listen-on-port 9905", "accept-from-host 127.0.0.1"],
    ["protocol udp", "listen-on-port 9905", "accept-from-host localhost"],
    );

# additional invalid/unsupported sources.  these require IPFIX
my @sources_bad_ipfix = (
    # repeat the unique (listen-on-port, listen-as-host, accept-from-host)
    # check for IPFIX probes on tcp
    [$probe_types[1],
     "protocol tcp", "listen-on-port 9901"],
    [$probe_types[1],
     "protocol tcp", "listen-on-port 9901"],
    [$probe_types[1],
     "protocol tcp", "listen-on-port 9902", "listen-as-host 127.0.0.1"],
    [$probe_types[1],
     "protocol tcp", "listen-on-port 9902", "listen-as-host 127.0.0.1"],
    [$probe_types[1],
     "protocol tcp", "listen-on-port 9903", "listen-as-host 127.0.0.1"],
    [$probe_types[1],
     "protocol tcp", "listen-on-port 9903", "listen-as-host localhost"],
    [$probe_types[1],
     "protocol tcp", "listen-on-port 9904", "accept-from-host 127.0.0.1"],
    [$probe_types[1],
     "protocol tcp", "listen-on-port 9904", "accept-from-host 127.0.0.1"],
    [$probe_types[1],
     "protocol tcp", "listen-on-port 9905", "accept-from-host 127.0.0.1"],
    [$probe_types[1],
     "protocol tcp", "listen-on-port 9905", "accept-from-host localhost"],
    # different probe-types on same protocol and port
    [$probe_types[0], "protocol udp", "listen-on-port 9906"],
    [$probe_types[1], "protocol udp", "listen-on-port 9906"],
    );

# valid ways to limit collection to particular hosts
my %probe_host = (
    'ipv4' => [
        ["listen-as-host 127.0.0.1"],
        ["accept-from-host 127.0.0.1"],
        ["listen-as-host 127.0.0.1", "accept-from-host 127.0.0.1"],
    ],
    'ipv6' => [
        ["listen-as-host 2001:db8:192:168::22:22"],
        ["accept-from-host 2001:db8:192:168::22:22"],
        ["listen-as-host 2001:db8:192:168::22:22",
         "accept-from-host 2001:db8:192:168::22:22"],
    ],
    'name' => [
        ["listen-as-host localhost"],
        ["accept-from-host localhost"],
        ["listen-as-host localhost", "accept-from-host localhost"],
    ],
    );

# valid and invalid log-flags
my @probe_log_flags = (
    ["log-flags all"],
    ["log-flags none"],
    ["log-flags bad"],
    ["log-flags missing"],
    ["log-flags junk"],
    ["log-flags bad, missing"],
    ["log-flags all none"],
    );

# valid and invalid priorities
my @probe_priorities = (
    ["priority 25"],
    ["priority 125"],
    );

# valid and invalid interface-values
my @probe_interface_values = (
    ["interface-values snmp"],
    ["interface-values vlan"],
    ["interface-values junk"],
    );

# valid and invalid quirks
my @quirks_flags = (
    ["quirks none"],
    ["quirks firewall-event"],
    ["quirks missing-ips"],
    ["quirks zero-packets"],
    ["quirks missing-ips zero-packets"],
    ["quirks none, zero-packets"],
    ["quirks all"],
    ["quirks junk"],
    );

# The following are used to create groups and sensors
my @sensor_networks = qw(internal external null);

my @interfaces = (
    '7',
    '7,8',
    'remainder');

my @ipblocks_v4 = (
    '172.16.22.22/31',
    '172.16.22.22, 172.16.22.23',
    'remainder');

my @ipblocks_v6 = (
     '2001:db8:172:16::22:22/127',
     '2001:db8:172:16::22:22 2001:db8:172:16::22:23',
     'remainder');

my @ipsets_v4 = (
    qq("$file{v4set1}"),
    $file{v4set2},
    'remainder');

my @ipsets_v6 = (
    $file{v6set1},
    qq("$file{v6set2}"),
    'remainder');


###########################################################################

# the current sensor.conf file
my $sensor_conf;

# variables used to uniquify probe and sensor names
my $probe = 0;
my $group = 0;
my $sensor = 0;

# names of a valid sensor added to every file to avoid "no valid
# sensor" error. Since files include other files, use unique name in
# each file.
my @valid_sensors = ();

# keeps track of all sensor names, so we can create a valid silk.conf file
my @sensor_list = ();

# keeps track of all sensor.conf files
my @sensor_files = ();

# md5 hashes we expect for each file, keys by the file name
my %md5_sums = ();

# variable to uniquify ports
my $port;


##########################################################################
#
#  Test generation code begins here


# for each probe type, create a sensor.conf file that uses each valid
# source, though not all sources are valid for all probes.
for my $pt (@probe_types) {

    $sensor_conf = open_sensorconf("valid-$pt", *SENSOR);
    if ($pt eq 'netflow-v5') {
        $md5_sums{$sensor_conf} = "eb0a541121a7a182eb17a664a314d611";
    }
    elsif ($pt eq 'silk') {
        $md5_sums{$sensor_conf} = "fc39db2e2fc11e1730127bb9c142a5dc";
    }
    elsif ($pt eq 'ipfix') {
        $md5_sums{$sensor_conf} = (($SiLKTests::SK_ENABLE_IPFIX)
                                   ? $md5_no_output
                                   : "e9febfa0917a41d03d0e11a906466209");
    }
    elsif ($pt eq 'netflow-v9') {
        $md5_sums{$sensor_conf} = (($SiLKTests::SK_ENABLE_IPFIX)
                                   ? "6491c4f7bcbe5e28920b4afa636285d2"
                                   : "3d2c3d0797739474cccbf590d324c3b0");
    }
    elsif ($pt eq 'sflow') {
        $md5_sums{$sensor_conf} = (($SiLKTests::SK_ENABLE_IPFIX)
                                   ? "fb56bd4d7f417e6854afde7087fa653a"
                                   : "c999322f7bb9d221acc56157ca8d3b0b");
    }
    else {
        die "$NAME: Unexpected probe_type '$pt'";
    }

    for my $lines (@sources_valid) {
        my $name = sprintf("PROBE-%04d", ++$probe);

        # make certain file/directory names are unique
        my $body = join "\n    ", @{$lines};
        $body =~ s,(incoming-nf),$1-$probe,;

        print SENSOR <<EOF;
probe $name $pt
    $body
end probe
EOF
    }
    close_sensorconf($sensor_conf, *SENSOR);
}



# using a netflow probe, create a sensor.conf file that uses each
# invalid source
$sensor_conf = open_sensorconf("badsource", *SENSOR);
$md5_sums{$sensor_conf} = "3a5ec7e73127ccd14998f5b36020c83e";
for my $lines (@sources_bad) {
    my $name = sprintf("PROBE-%04d", ++$probe);

    # make certain file/directory names are unique
    my $body = join "\n    ", @{$lines};
    $body =~ s,(incoming-nf),$1-$probe,;

    print SENSOR <<EOF;
probe $name $probe_types[0]
    $body
end probe
EOF
}
close_sensorconf($sensor_conf, *SENSOR);


# additional invalid sources; these tests require IPFIX
$sensor_conf = open_sensorconf("badsource-ipfix", *SENSOR);
$md5_sums{$sensor_conf} = (($SiLKTests::SK_ENABLE_IPFIX)
                           ? "e287169ca89490e576ed079ff5054847"
                           : "47be355aa649b553470bc2a47721b057");
for my $lines (@sources_bad_ipfix) {
    my $name = sprintf("PROBE-%04d", ++$probe);

    # pull the probe-type from the input
    my $ptype = shift @{$lines};

    # make certain file/directory names are unique
    my $body = join "\n    ", @{$lines};
    $body =~ s,(incoming-nf),$1-$probe,;

    print SENSOR <<EOF;
probe $name $ptype
    $body
end probe
EOF
}
close_sensorconf($sensor_conf, *SENSOR);


# use a netflow probe listening on a port and add various host clauses
# to it.  create a separate file for each of ipv4, ipv6, names
for my $key (sort keys %probe_host) {

    $sensor_conf = open_sensorconf("netflow-host-$key", *SENSOR);
    if ($key eq 'ipv4') {
        $md5_sums{$sensor_conf} = $md5_no_output;
    }
    elsif ($key eq 'ipv6') {
        $md5_sums{$sensor_conf} = (($SiLKTests::SK_ENABLE_INET6_NETWORKING)
                                   ? $md5_no_output
                                   : "53b9dbfe28c70657e881b6d789baede5");
    }
    elsif ($key eq 'name') {
        $md5_sums{$sensor_conf} = $md5_no_output;
    }
    else {
        die "$NAME: Unexpected value in \%probe_host: '$key'";
    }

    # modify port for each probe
    $port = 9900;

    for my $lines (@{$probe_host{$key}}) {
        my $name = sprintf("PROBE-%04d", ++$probe);
        ++$port;

        # make certain file/directory names are unique
        my $body = join "\n    ", @{$lines};
        $body =~ s,(incoming-nf),$1-$probe,;

        print SENSOR <<EOF;
probe $name $probe_types[0]
    protocol udp
    listen-on-port $port
    $body
end probe
EOF
    }
    close_sensorconf($sensor_conf, *SENSOR);
}



# add various statements to valid NetFlow v5 probes
$sensor_conf = open_sensorconf("netflow-extras", *SENSOR);
$md5_sums{$sensor_conf} = "5f93cf6c0fab82c72ef69c21685b9afd";
$port = 9900;
for my $lines (@probe_priorities, @probe_log_flags,
               @probe_interface_values, @quirks_flags)
{
    my $name = sprintf("PROBE-%04d", ++$probe);
    ++$port;

    # make certain file/directory names are unique
    my $body = join "\n    ", @{$lines};
    $body =~ s,(incoming-nf),$1-$probe,;

    print SENSOR <<EOF;
probe $name $probe_types[0]
    protocol udp
    listen-on-port $port
    $body
end probe
EOF
}
close_sensorconf($sensor_conf, *SENSOR);



# add the interface-value statements to an IPFIX probe
$sensor_conf = open_sensorconf("ipfix-iface-values", *SENSOR);
$md5_sums{$sensor_conf} = (($SiLKTests::SK_ENABLE_IPFIX)
                           ? "37875a828df890726def606fea8ec26a"
                           : "cd13db37bfa9e11b1e4601d15f7cec66");
$port = 9900;
for my $lines (@probe_interface_values) {
    my $name = sprintf("PROBE-%04d", ++$probe);
    ++$port;

    # make certain file/directory names are unique
    my $body = join "\n    ", @{$lines};
    $body =~ s,(incoming-nf),$1-$probe,;

    print SENSOR <<EOF;
probe $name ipfix
    protocol tcp
    listen-on-port $port
    $body
end probe
EOF
}
close_sensorconf($sensor_conf, *SENSOR);



# create a file to hold the main group definitions, and remember this
# file's name
$sensor_conf = open_sensorconf("groups-main", *SENSOR);
$md5_sums{$sensor_conf} = $md5_no_output;
my $group_file = $sensor_conf;

for my $list_type (qw(interfaces ipblocks ipsets)) {
    my $list;
    if ($list_type eq 'interfaces') {
        $list = \@interfaces;
    }
    elsif ($list_type eq 'ipblocks') {
        $list = \@ipblocks_v4;
    }
    elsif ($list_type eq 'ipsets') {
        $list = \@ipsets_v4;
    }
    else {
        die "$NAME: Unexpected \$list_type '$list_type'";
    }

    for my $i (@$list) {
        next if $i eq 'remainder';

        my $name = sprintf("GROUP-%04d", ++$group);
        if ($i eq $list->[0]) {
            # this allows this group name to be used in the future
            push @$list, '@'.$name;
        }

        print SENSOR <<EOF;
group $name
    $list_type $i
end group
EOF
    }
}
close_sensorconf($sensor_conf, *SENSOR);


# use the @GROUP-* names we added to make some valid and invalid group
# names
$sensor_conf = open_sensorconf("sensors-groups-invalid", *SENSOR);
$md5_sums{$sensor_conf} = "2865fd875708602dc39aef3ab595244c";
print SENSOR "include \"$group_file\"\n";
for my $g ($interfaces[-1], $ipblocks_v4[-1], $ipsets_v4[-1], '@NOT_EXIST') {
    for my $i ('interfaces 0', 'ipblocks 64.0.0.0/8', "ipsets $file{v4set1}") {

        my $name = sprintf("GROUP-%04d", ++$group);

        print SENSOR <<EOF;
group $name
    $i
    $i, $g
end group
EOF
    }
}
close_sensorconf($sensor_conf, *SENSOR);



# create a another file to hold only the groups of IPv6 addresses
$sensor_conf = open_sensorconf("groups-ipv6", *SENSOR);
$md5_sums{$sensor_conf} = (($SiLKTests::SK_ENABLE_IPV6)
                           ? $md5_no_output
                           : "947ce664fa0299c3dcafb6fc304d92f0");
for my $list_type (qw(ipblocks ipsets)) {
    my $list;
    if ($list_type eq 'ipblocks') {
        $list = \@ipblocks_v6;
    }
    elsif ($list_type eq 'ipsets') {
        $list = \@ipsets_v6;
    }
    else {
        die "$NAME: Unexpected \$list_type '$list_type'";
    }

    for my $i (@$list) {
        next if $i eq 'remainder';

        my $name = sprintf("GROUP-%04d", ++$group);
        # we never reference these IPv6 groups, so no need to cache
        # the name

        print SENSOR <<EOF;
group $name
    $list_type $i
end group
EOF
    }
}
close_sensorconf($sensor_conf, *SENSOR);



# create sensors that use source-network/destination-network
for my $pt (@probe_types) {

    $sensor_conf = open_sensorconf("sensors-network-$pt", *SENSOR);

    # currently supported by all probe types
    $md5_sums{$sensor_conf} = $md5_no_output;

    for my $src (@sensor_networks) {
        for my $dst (@sensor_networks) {

            my $name = sprintf("SENSOR-%04d", ++$sensor);
            push @sensor_list, $name;

            print SENSOR <<EOF;
sensor $name
    $pt-probes PROBE-$pt
    source-network $src
    destination-network $dst
end sensor
EOF
        }
    }
    close_sensorconf($sensor_conf, *SENSOR);
}



# create sensors that use ipblocks, ipsets, or interfaces.  some of
# these are valid and some are not
srand(627389505);
$sensor_conf = open_sensorconf("sensors-ip-interface", *SENSOR);
$md5_sums{$sensor_conf} = "2f51f895857623bb3fa487f4d3d36fa6";
print SENSOR "include \"$group_file\"\n";
for my $nw (@sensor_networks) {
    # this block only uses the networks $src_nw and $dst_nw, and they
    # are set to whatever is NOT the current index of this for() loop
    my ($src_nw, $dst_nw) = grep !/$nw/, @sensor_networks;

    my @null_interface;
    if ($dst_nw eq 'null') {
        @null_interface = ("");
    }
    else {
        @null_interface = ("", "\n    null-interface 0");
    }

    for my $if_type (qw(interfaces ipblocks ipsets)) {
        my ($src_if_list, $dst_if_list);
        if ($if_type eq 'interfaces') {
            $src_if_list = \@interfaces;
            $dst_if_list = \@interfaces;
        }
        elsif ($if_type eq 'ipblocks') {
            $src_if_list = \@ipblocks_v4;
            $dst_if_list = \@ipblocks_v4;
        }
        elsif ($if_type eq 'ipsets') {
            $src_if_list = \@ipsets_v4;
            $dst_if_list = \@ipsets_v4;
        }
        else {
            die "$NAME: Unexpected \$if_type '$if_type'";
        }

        for my $src_if (@$src_if_list) {
            for my $dst_if (@$dst_if_list) {
                for my $null_stmt (@null_interface) {

                    # discard-when/discard-unless
                    my $discard = "";

                    for my $dis_phrase ('source-ipblocks 10.0.0.0/8',
                                        'destination-ipblocks 11.0.0.0/8',
                                        'any-ipblocks '.$ipblocks_v4[-1],
                                        'source-interfaces 10',
                                        'destination-interfaces 11',
                                        'any-interfaces '.$interfaces[-1],
                                        'source-ipsets '.$file{v4set1},
                                        qq'destination-ipsets "$file{v4set1}"',
                                        'any-ipsets '.$ipsets_v4[-1],)
                    {
                        my $chance = rand 20;
                        if ($chance < 2) {
                            $discard .= "\n    discard-when $dis_phrase";
                        }
                        elsif ($chance < 4) {
                            $discard .= "\n    discard-unless $dis_phrase";
                        }
                        # else do nothing
                    }

                    my $name = sprintf("SENSOR-%04d", ++$sensor);
                    push @sensor_list, $name;

                    print SENSOR <<EOF;
sensor $name
    $probe_types[0]-probes PROBE-$probe_types[0]$discard
    $src_nw-$if_type $src_if
    $dst_nw-$if_type $dst_if$null_stmt
end sensor
EOF
                }
            }
        }
    }
}
close_sensorconf($sensor_conf, *SENSOR);



# this block is similar the preceeding, except is uses IPv6 addresses.
# Much less is checked here.
$sensor_conf = open_sensorconf("sensors-ipv6", *SENSOR);
$md5_sums{$sensor_conf} = (($SiLKTests::SK_ENABLE_IPV6)
                           ? "62ad94cce7b4f5741d84880d0b2f0248"
                           : "dce8971fe918cc0e28924234d00e3344");
print SENSOR "include \"$group_file\"\n";

for my $nw (@sensor_networks) {
    # this block only uses the networks $src_nw and $dst_nw, and they
    # are set to whatever is NOT the current index of this for() loop
    my ($src_nw, $dst_nw) = grep !/$nw/, @sensor_networks;

    my @null_interface;
    if ($dst_nw eq 'null') {
        @null_interface = ("");
    }
    else {
        @null_interface = ("", "\n    null-interface 0");
    }

    for my $if_type (qw(ipblocks ipsets)) {
        my ($src_if_list, $dst_if_list);
        if ($if_type eq 'ipblocks') {
            $src_if_list = \@ipblocks_v6;
            $dst_if_list = \@ipblocks_v6;
        }
        elsif ($if_type eq 'ipsets') {
            $src_if_list = \@ipsets_v6;
            $dst_if_list = \@ipsets_v6;
        }
        else {
            die "$NAME: Unexpected \$if_type '$if_type'";
        }

        for my $src_if (@$src_if_list) {
            for my $dst_if (@$dst_if_list) {
                for my $null_stmt (@null_interface) {

                    my $name = sprintf("SENSOR-%04d", ++$sensor);
                    push @sensor_list, $name;

                    print SENSOR <<EOF;
sensor $name
    $probe_types[0]-probes PROBE-$probe_types[0]
    $src_nw-$if_type $src_if
    $dst_nw-$if_type $dst_if$null_stmt
end sensor
EOF
                }
            }
        }
    }
}
close_sensorconf($sensor_conf, *SENSOR);



# check handling of duplicate source/destination
$sensor_conf = open_sensorconf("sensors-duplicate", *SENSOR);
$md5_sums{$sensor_conf} = "e0d426e5c404e99b2d43df044363ec8d";
for my $sd (qw/source destination/) {
    my $name = sprintf("SENSOR-%04d", ++$sensor);
    push @sensor_list, $name;

    print SENSOR <<EOF;
sensor $name
    $probe_types[0]-probes PROBE-$probe_types[0]
    source-network internal
    destination-network external
    $sd-network internal
end sensor
EOF
}
# check handling of duplicate network
for my $nw (@sensor_networks) {
    my $name = sprintf("SENSOR-%04d", ++$sensor);
    push @sensor_list, $name;

    print SENSOR <<EOF;
sensor $name
    $probe_types[0]-probes PROBE-$probe_types[0]
    internal-interfaces 4
    external-interfaces 5
    null-interfaces 6
    $nw-interfaces 7
end sensor
EOF
}
close_sensorconf($sensor_conf, *SENSOR);


# Create a silk.conf file that defines all the sensor names that were
# created.
my $silk_conf = "$tmpdir/silk.conf";
open SILK, ">$silk_conf"
    or die "$NAME: Cannot open $silk_conf: $!\n";
push @sensor_list, @valid_sensors;

for (my $i = 0, my $j = 1; $i < @sensor_list; ++$i, ++$j) {
    my $s = $sensor_list[$i];
    print SILK "sensor $j $s\n";
}

print SILK "group my-sensors\n";
for my $s (@sensor_list) {
    print SILK "    sensors $s\n";
}

print SILK <<EOF;
end group
class all
    sensors \@my-sensors
end class
class all
    type  0 in      in
    type  1 out     out
    type  2 inweb   iw
    type  3 outweb  ow
    type  4 innull  innull
    type  5 outnull outnull
    type  6 int2int int2int
    type  7 ext2ext ext2ext
    type  8 inicmp  inicmp
    type  9 outicmp outicmp
    type 10 other   other
    default-types in inweb inicmp
end class
packing-logic "packlogic-twoway.so"
EOF

close SILK
    or die "$NAME: Cannot close $silk_conf: $!\n";

# holds the names of tests where the checksum does not match
my @mismatch;

# run rwflowpack on each sensor.conf file and compare the checksum
for $sensor_conf (@sensor_files) {
    # trailing "; true" is here since check_exit_status() redirects
    # everything to /dev/null, and it ensures the return status is 0.
    if ($ENV{SK_TESTS_VERBOSE}) {
        unless (open SENSOR_CONF, '<', $sensor_conf) {
            warn "$NAME: Cannot open '$sensor_conf'\n";
            next;
        }
        print STDERR "\n>> START OF FILE '$sensor_conf' >>>>>>>>>>\n";
        while (<SENSOR_CONF>) {
            print STDERR $_;
        }
        close SENSOR_CONF;
        print STDERR "<< END OF FILE '$sensor_conf' <<<<<<<<<<<<\n";
    }
    my $cmd = ("$rwflowpack --site-conf=$silk_conf --sensor-conf=$sensor_conf"
               ." --verify-sensor >$sensor_conf.RAWOUT 2>&1"
               ." ; true");
    check_exit_status($cmd);

    # modify the output file to remove differences among different
    # runs or different OSes.
    open RAWOUT, "$sensor_conf.RAWOUT"
        or die "$NAME: Cannot open '$sensor_conf.RAWOUT': $!\n";
    open OUT, ">$sensor_conf.OUT"
        or die "$NAME: Cannot open '$sensor_conf.OUT': $!\n";

    if ($ENV{SK_TESTS_VERBOSE}) {
        print STDERR ">> START OF RESULT '$sensor_conf.RAWOUT' >>>>>>>>>>\n";
    }
    while (<RAWOUT>) {
        if ($ENV{SK_TESTS_VERBOSE}) {
            print STDERR $_;
        }

        # replace test-specific sensor config file name with "sensor.conf"
        s/\Q$sensor_conf\E/sensor.conf/g;

        # remove any error message from gai_error() since it may
        # differ across platforms; in addition, there is no error
        # message when using gethostbyname()
        s/(unable to resolve '2001:.* as an ipv4 address):.*/$1/i;

        print OUT;
    }
    if ($ENV{SK_TESTS_VERBOSE}) {
        print STDERR "<< END OF RESULT '$sensor_conf.RAWOUT' <<<<<<<<<<<<\n";
    }

    close RAWOUT;
    close OUT
        or die "$NAME: Cannot close '$sensor_conf.OUT': $!\n";

    # compute MD5 of the file and compare to expected value; if there
    # is not a match, put name into @mismatch.
    my $md5;
    compute_md5_file(\$md5, "$sensor_conf.OUT");
    if ($md5_sums{$sensor_conf} ne $md5) {
        if ($ENV{SK_TESTS_VERBOSE}) {
            print STDERR "$NAME: FAIL: checksum mismatch [$md5]",
                " (expected ", $md5_sums{$sensor_conf}, ")\n";
        }
        my $tail_name = "$sensor_conf.OUT";
        $tail_name =~ s,.*/,,;
        push @mismatch, $tail_name;
    }
    elsif ($ENV{SK_TESTS_VERBOSE}) {
        print STDERR "$NAME: PASS: checksums match\n";
    }
}

if ($ENV{SK_TESTS_SAVEOUTPUT}) {
    # when saving the output, write a file that combines each probe,
    # sensor, or group block with the errors it generated (if any)
    combine_sensor_and_error();
}

# print names of first few files that don't match
if (@mismatch) {
    if (@mismatch == 1) {
        die "$NAME: Found 1 checksum miss: @mismatch\n";
    }
    elsif (@mismatch <= 5) {
        die("$NAME: Found ", scalar(@mismatch), " checksum misses: ",
            join(", ", @mismatch), "\n");
    }
    else {
        die("$NAME: Found ", scalar(@mismatch), " checksum misses: ",
            join(", ", @mismatch[0..4], "..."), "\n");
    }
}

exit 0;


sub open_sensorconf
{
    my ($description, $glob) = @_;

    our $conf_count;
    ++$conf_count;

    # get line number where invoked
    my $src_line = (caller)[2];

    # use last 23 characters of description as sensor name
    our $valid_sensor = substr($description, -23);
    push @valid_sensors, $valid_sensor;

    my $conf = sprintf("%s/sc%02d-%s.conf",
                       $tmpdir, $conf_count, $description);
    push @sensor_files, $conf;

    open $glob, ">$conf"
        or die "$NAME: Cannot open '$conf': $!\n";

    print $glob <<EOF;
# open_sensorconf("$description") called from line $src_line
EOF

    return $conf;
}

sub close_sensorconf
{
    my ($file, $glob) = @_;

    our $valid_sensor;

    # get line number where invoked
    my $src_line = (caller)[2];

    # print a valid sensor to the file to avoid an error about the
    # file not having a valid sensor
    print $glob <<EOF;
sensor $valid_sensor
    silk-probes $valid_sensor
    source-network internal
    destination-network internal
end sensor
# close_sensorconf() called from line $src_line
EOF

    close $glob
        or die "$NAME: Cannot close '$file': $!\n";
}



sub combine_sensor_and_error
{
    # This subroutine is to help debug the test in this file.
    #
    # This subroutine finds each probe/sensor/group block in the
    # various sensor.conf files (named scNN-<description>.conf and
    # each error message block in the output files (these files have
    # ".OUT" appended to the sensor.conf name).
    #
    #  If an input block did not produce an error, this subroutine
    #  produces the output:
    #
    #    #line NNNN FILE
    #    <text of block>
    #
    # where NNNN and FILE are the line number and filename name where the
    # block began.
    #
    # If an input block does produce an error, the subroutine writes the
    # output
    #
    #    #line NNNN FILE
    #    <text of block>
    #    #<text of error>
    #
    # where each line of the error is proceeded by '#'.
    #
    # The subroutine writes a newline before every #line statement.
    #
    # This subroutine writes its output to a file named "COMBINED.txt"
    # in the output directory.
    #

    # open the output file
    my $combined = "$tmpdir/COMBINED.txt";
    open COMBINED, ">$combined"
        or return;
    print COMBINED "TMPDIR=$tmpdir\n";

    # create a copy of the sensor file list
    our @input_files = (@sensor_files);
    our @error_files;

    for (@input_files) {
        push @error_files, "$_.OUT";
    }

    # find the first error
    my $error = {};
    my $more_errors = combine_get_error($error);

    # process all the blocks
    my $block = {};
    while (combine_get_block($block)) {
        # print the block
        print COMBINED ($block->{preamble}, "\n",
                        $block->{line}, "\n",
                        $block->{text});

        # print the error if it matches this block
        if ($more_errors) {
            if ($error->{name}
                && ($block->{name} eq $error->{name}))
            {
                print COMBINED $error->{text};
                $more_errors = combine_get_error($error);
            }
        }
    }

    close COMBINED;
}

#  $got_block = combine_get_block(\%block)
#
#    Helper function for combine_sensor_and_error().
#
#    Find the next probe/sensor/group block from the @input_files and
#    fill in the hash reference 'block' with that information.  Return
#    1 if a block was found, or 0 if not.
#
sub combine_get_block
{
    my ($block) = @_;
    $block->{text} = "";
    $block->{name} = "";
    $block->{line} = "";
    $block->{preamble} = "";

    our @input_files;
    our $sen_fh;
    our $sen_lc;
    our $sen_file;

    while (@input_files || defined $sen_fh) {

        if (!defined $sen_fh) {
            if (!@input_files) {
                return 0;
            }
            $sen_file = shift @input_files;
            open $sen_fh, $sen_file
                or die "$NAME: Cannot open '$sen_file': $!\n";
            $sen_file =~ s|^\Q$tmpdir\E|\$TMPDIR|;
            $sen_lc = 1;
            $block->{preamble} = ("#" x 70)."\n#include \"$sen_file\"\n";
        }

        while (defined(my $sen_line = <$sen_fh>)) {
            # print blank lines, comments, include statements
            if ($sen_line =~ /^\s*$/
                || $sen_line =~ /^#/
                || $sen_line =~ /^include/)
            {
                $block->{preamble} .= $sen_line;
                ++$sen_lc;
                next;
            }
            die "$NAME: Bad line $sen_file:$sen_lc: '$sen_line'\n"
                unless $sen_line =~ /^(probe|group|sensor) (\S+)/;
            $block->{name} = $2;
            $block->{line} = "#line $sen_lc \"$sen_file\"";
            $block->{text} = $sen_line;
            my $block_type = $1;
            ++$sen_lc;
            while (defined($sen_line = <$sen_fh>)) {
                $block->{text} .= $sen_line;
                ++$sen_lc;
                if ($sen_line =~ /end $block_type/) {
                    return 1;
                }
            }
        }
        close $sen_fh;
        undef $sen_fh;
    }
    return 0;
}

#  $got_err = combine_get_error(\%error)
#
#    Helper function for combine_sensor_and_error().
#
#    Find the next error block from the @error_files and fill in the
#    hash reference 'error' with that information.  Return 1 if an
#    error was found, or 0 if not.
#
sub combine_get_error
{
    my ($error) = @_;
    $error->{name} = undef;
    $error->{text} = "";

    our @error_files;
    our $err_fh;

    while (@error_files || defined $err_fh) {

        if (!defined $err_fh) {
            if (!@error_files) {
                return 0;
            }
            my $f = shift @error_files;
            open $err_fh, $f
                or die "$NAME: Cannot open '$f': $!\n";
        }

        while (defined(my $e = <$err_fh>)) {
            $error->{text} .= "#".$e;
            if ($e =~ /Encountered \d+ error.*'((PROBE|GROUP|SENSOR)-\S+)'/) {
                $error->{name} = $1;
                return 1;
            }
        }
        close $err_fh;
        undef $err_fh;
    }
    return 0;
}

__END__
