## Copyright (C) 2009-2023 by Carnegie Mellon University.
##
## @OPENSOURCE_LICENSE_START@
##
## SiLK 3.22.0
##
## Copyright 2023 Carnegie Mellon University.
##
## NO WARRANTY. THIS CARNEGIE MELLON UNIVERSITY AND SOFTWARE ENGINEERING
## INSTITUTE MATERIAL IS FURNISHED ON AN "AS-IS" BASIS. CARNEGIE MELLON
## UNIVERSITY MAKES NO WARRANTIES OF ANY KIND, EITHER EXPRESSED OR IMPLIED,
## AS TO ANY MATTER INCLUDING, BUT NOT LIMITED TO, WARRANTY OF FITNESS FOR
## PURPOSE OR MERCHANTABILITY, EXCLUSIVITY, OR RESULTS OBTAINED FROM USE OF
## THE MATERIAL. CARNEGIE MELLON UNIVERSITY DOES NOT MAKE ANY WARRANTY OF
## ANY KIND WITH RESPECT TO FREEDOM FROM PATENT, TRADEMARK, OR COPYRIGHT
## INFRINGEMENT.
##
## Released under a GNU GPL 2.0-style license, please see LICENSE.txt or
## contact permission@sei.cmu.edu for full terms.
##
## [DISTRIBUTION STATEMENT A] This material has been approved for public
## release and unlimited distribution.  Please see Copyright notice for
## non-US Government use and distribution.
##
## GOVERNMENT PURPOSE RIGHTS - Software and Software Documentation
##
## Contract No.: FA8702-15-D-0002
## Contractor Name: Carnegie Mellon University
## Contractor Address: 4500 Fifth Avenue, Pittsburgh, PA 15213
##
## The Government's rights to use, modify, reproduce, release, perform,
## display, or disclose this software are restricted by paragraph (b)(2) of
## the Rights in Noncommercial Computer Software and Noncommercial Computer
## Software Documentation clause contained in the above identified
## contract. No restrictions apply after the expiration date shown
## above. Any reproduction of the software or portions thereof marked with
## this legend must also reproduce the markings.
##
## Carnegie Mellon(R) and CERT(R) are registered in the U.S. Patent and
## Trademark Office by Carnegie Mellon University.
##
## This Software includes and/or makes use of Third-Party Software each
## subject to its own license.
##
## DM23-0973
##
## @OPENSOURCE_LICENSE_END@
##
#######################################################################
#  SiLKTests.pm
#
#  Mark Thomas
#  March 2009
#
#######################################################################
#  RCSIDENT("$SiLK: SiLKTests.pm 576b96bec358 2023-04-24 19:28:00Z mthomas $")
#######################################################################
#
#    Perl module used by the scripts that "make check" runs.
#
#######################################################################
#
#    This module is also used by the various make-tests.pl scripts
#    that generate the tests that "make check" runs.
#
#    In make-tests.pl, each test is defined by a tuple, which contains
#    two positional arguments and multiple keyed arguments.  The first
#    two arguments must be (1)the test-name, (2)a variable denoting
#    the type of test:
#
#    -- $SiLKTests::STATUS
#
#       An exit-status-only test.  The command is run and its exit
#       status is compared to see if it matches the expected value.
#       If the values match the test passes; otherwise it fails.
#
#    -- $SiLKTests::MD5
#
#       The command is run and its output is captured.  If the command
#       fails to run or exit with a non-zero exit status, the test
#       fails.  The md5 checksum of the output is computed and
#       compared with the expected value.  If the values match the
#       test passes; otherwise it fails.
#
#    -- $SiLKTests::ERR_MD5
#
#       The same as $SiLKTests::MD5, except that the command MUST exit
#       with a non-zero exit status.  One use of this is to determine
#       whether a command is failing with the correct error message.
#
#    -- $SiLKTests::CMP_MD5
#
#       Runs two different commands and determines whether the MD5
#       checksum of their outputs is identical.  If they are
#       identical, the test passes.  If either command exits with a
#       non-zero exit status, the test fails.
#
#    The remaining members of the tuple are key/value pairs, where the
#    keys and their values are (note that keys include the single
#    leading hyphen):
#
#    -file
#
#        Array reference of data file keys the test uses.  The test
#        should refer to them as $file{key}.  These files must exist
#        in the $top_builddir/tests/. directory.  If these files do
#        not exist when the test is run, the test will be skipped.
#
#    -app
#
#        Array reference of other SiLK applications required by the
#        test.  The test should refer to them by name, e.g., $rwcat.
#        If these applications do not exist when the test is run, the
#        test will be skipped.
#
#    -env
#
#        Hash reference of environment variable names and values that
#        should be set.
#
#    -lib
#
#        Array reference of directories.  The LD_LIBRARY_PATH, or
#        equivalent, will be set to include these directories.  Used
#        to test plug-in support.
#
#    -temp
#
#        Array reference of name keys.  These will be replaced by
#        temporary files, with the same name being mapped to the same
#        file.  The test should refer to them as $temp{key}.  The test
#        should not rely on the file name, since that will differ with
#        each run.
#
#    -features
#
#        Array reference of feature keys.  This adds a call to the
#        check_features() function in the generated script, and uses
#        the elements in the array reference as the arguments to the
#        function.  See the check_features() function for the
#        supported list of keys.
#
#    -pretest
#
#        Adds arbitrary code to the generated test.
#
#    -exit77
#
#        Text to add directly to the test file being created.  When
#        the test is run, this text will be treated as the body of a
#        subroutine to be called with no arguments.  If the sub
#        returns TRUE, the test will exit with exit code 77.  This is
#        a way to skip tests for features that may not have been
#        compiled into SiLK.
#
#    -testfile
#
#        Use the specified value as the name of the test file instead
#        of the default, $APP-$test_name, where $APP is the name of
#        the application passed to make_test_scripts() and $test_name
#        is the name of the test.
#
#    -cmd
#
#        Either a single command string or an array reference
#        containing one or more command strings.
#
#######################################################################
#
#    Environment variables affecting tests
#
#    -- SK_TESTS_VERBOSE
#
#       Print commands before they get executed.  If this value is not
#       specified in the environment, it defaults to TRUE.
#
#    -- SK_TESTS_SAVEOUTPUT
#
#       Normally once the output of the command is used to compute the
#       MD5 checksum, the output is forgotten.  When this variable is
#       set, the output used to compute the MD5 checksum is saved.
#       This variable also prevents the removal of any temporary files
#       that were used by the command
#
#    -- SK_TESTS_VALGRIND
#
#       If set, its value is expected to be the path to the valgrind
#       tool and any command line switches to pass to valgrind, for
#       example "SK_TESTS_VALGRIND='valgrind -v --leak-check=full'"
#
#       Do not include the --log-file switch.  The testing framework
#       will run the application under valgrind and write the results
#       to the tests directory with the name
#       "<TEST_NAME>.<APPLICATION>.<PID>.vg" where TEST_NAME is the
#       name of test, APPLICATION is the name of the application, and
#       PID is the process id.
#
#       TODO: Currently this environment variable runs the application
#       under libtool if necessary; it would be nice to have a second
#       environment variable that points to the installed applications
#       to bypass the libtool mess.
#
#    -- SK_TESTS_LOG_DEBUG
#
#       Used by "make check" when running daemons.  When this variable
#       is set, the test adds a --log-level=debug switch to the
#       daemon's command line.
#
#    -- SK_TESTS_MAKEFILE
#
#       Used by make-tests.pl.  When this variable is set, the new
#       TESTS and XFAIL_TESTS variables are appended to the
#       Makefile.am file.  The user should remove the previous values
#       before running automake.
#
#    -- SK_TESTS_CHECK_MAKEFILE
#
#       Similar to SK_TESTS_MAKEFILE, except the Makefile.am file is
#       not updated.  Instead, a message is printed noting how the
#       TESTS and XFAIL_TESTS variables need to be modified.
#
#    -- SK_TESTS_DEBUG_SCRIPTS
#
#       Used by make-tests.pl.  When this variable is set, the body of
#       the script that make-tests.pl runs to determine the correct
#       output is printed.
#
#######################################################################

package SiLKTests;

use strict;
use warnings;
use Carp;
use IO::Socket::INET qw();
use File::Temp;


END {
}


BEGIN {
    our $NAME = $0;
    $NAME =~ s,.*/,,;

    #  Set the required variables from the environment
    our $srcdir = $ENV{srcdir};
    our $top_srcdir = $ENV{top_srcdir};
    our $top_builddir = $ENV{top_builddir};
    unless (defined $srcdir && defined $top_srcdir && defined $top_builddir) {
        # do not use skip_test(), it is not defined yet
        my @not_defined =
            grep {!defined $ENV{$_}} qw(srcdir top_srcdir top_builddir);
        warn("$NAME: Skipping test: The following environment",
             " variable", ((@not_defined > 1) ? "s are" : " is"),
             " not defined: @not_defined\n");
        exit 77;
    }

    #  Make certain MD5 is available
    eval { require Digest::MD5; Digest::MD5->import; };
    if ($@) {
        # do not use skip_test(), it is not defined yet
        warn "$NAME: Skipping test: Digest::MD5 module not available\n";
        exit 77;
    }

    our $testsdir = "$top_builddir/tests";
    require "$testsdir/config-vars.pm";

    #  Set up the Exporter and export variables
    use Exporter ();
    our ($VERSION, @ISA, @EXPORT, @EXPORT_OK, %EXPORT_TAGS);

    # set the version for version checking
    $VERSION     = 1.00;

    @ISA         = qw(Exporter);
    @EXPORT      = qw(&add_plugin_dirs &check_app_switch
                      &check_daemon_init_program_name
                      &check_exit_status &check_features
                      &check_md5_file &check_md5_output
                      &check_python_bin &check_python_plugin
                      &check_silk_app &compute_md5 &compute_md5_file
                      &get_data_or_exit77 &get_datafile
                      &get_ephemeral_port &make_config_file
                      &make_packer_sensor_conf
                      &make_tempdir &make_tempname &make_test_scripts
                      &print_tests_hash &run_command
                      &rwpollexec_use_alternate_shell &skip_test
                      &verify_archived_files &verify_directory_files
                      &verify_empty_dirs
                      $srcdir $top_srcdir
                      );
    %EXPORT_TAGS = ( );
    @EXPORT_OK   = ( );  #qw($Var1 %Hashit &func3);


    # These define the type of tests to run.
    our $STATUS = 0;  # Just check exit status of command
    our $MD5 = 1;     # Check MD5 checksum of output against known value
    our $ERR_MD5 = 2; # Check MD5 checksum, expect cmd to exit non-zero
    our $CMP_MD5 = 3; # Compare the MD5 checksums of two commands

    our $PWD = `pwd`;
    chomp $PWD;

    # Default to being verbose
    unless (defined $ENV{SK_TESTS_VERBOSE}) {
        $ENV{SK_TESTS_VERBOSE} = 1;
    }

    # List of features used by check_features().
    our %feature_hash = (
        gnutls      => sub {
            skip_test("No GnuTLS support")
                unless 1 == $SiLKTests::SK_ENABLE_GNUTLS;
        },
        ipa         => sub {
            skip_test("No IPA support")
                unless 1 == $SiLKTests::SK_ENABLE_IPA;
        },
        ipfix       => sub {
            skip_test("No IPFIX support")
                unless 1 == $SiLKTests::SK_ENABLE_IPFIX;
        },
        inet6       => sub {
            skip_test("No IPv6 networking support")
                unless $SiLKTests::SK_ENABLE_INET6_NETWORKING;
        },
        ipset_v6    => sub {
            skip_test("No IPv6 IPset support")
                unless ($SiLKTests::SK_ENABLE_IPV6);
        },
        ipv6        => sub {
            skip_test("No IPv6 Flow record support")
                unless $SiLKTests::SK_ENABLE_IPV6;
        },
        netflow9    => sub {
            skip_test("No NetFlow V9 support")
                unless ($SiLKTests::SK_ENABLE_IPFIX);
        },
        stdin_tty   => sub {
            skip_test("stdin is not a tty")
                unless (-t STDIN);
        },
        );

}
our @EXPORT_OK;

our $top_builddir;
our $top_srcdir;
our $testsdir;
our $srcdir;
our $STATUS;
our $MD5;
our $ERR_MD5;
our $CMP_MD5;
our $NAME;

# list of environment variables to print in dump_env(), which is
# called when running a command.
our @DUMP_ENVVARS = qw(top_srcdir top_builddir srcdir
                       TZ LANG LC_ALL SILK_HEADER_NOVERSION
                       SILK_DATA_ROOTDIR SILK_CONFIG_FILE
                       SILK_COUNTRY_CODES SILK_ADDRESS_TYPES
                       SILK_COMPRESSION_METHOD
                       SILK_IPSET_RECORD_VERSION SKIPSET_INCORE_FORMAT
                       PYTHONPATH
                       LD_LIBRARY_PATH DYLD_LIBRARY_PATH LIBPATH SHLIB_PATH
                       G_SLICE G_DEBUG);

# whether to print contents of scripts that get run
our $DEBUG_SCRIPTS = $ENV{SK_TESTS_DEBUG_SCRIPTS};

# how to indent each line of the output
our $INDENT = "    ";

# ensure all commands are run in UTC timezone
$ENV{TZ} = "0";

# specify silk.conf file to use for all tests
$ENV{SILK_CONFIG_FILE} = "$top_builddir/tests/silk.conf";

# do not put the SiLK version number into binary SiLK files
$ENV{SILK_HEADER_NOVERSION} = 1;

# unset several environment variables
for my $e (qw(SILK_IP_FORMAT SILK_IPV6_POLICY SILK_PYTHON_TRACEBACK
              SILK_RWFILTER_THREADS SILK_TIMESTAMP_FORMAT
              SILK_LOGSTATS_RWFILTER SILK_LOGSTATS SILK_LOGSTATS_DEBUG))
{
    delete $ENV{$e};
}

# run the C locale
$ENV{LANG} = 'C';
$ENV{LC_ALL} = 'C';

# disable creating of *.pyc files in Python 2.6+
$ENV{PYTHONDONTWRITEBYTECODE} = 1;

my %test_files = (
    empty           => "$testsdir/empty.rwf",
    data            => "$testsdir/data.rwf",
    v6data          => "$testsdir/data-v6.rwf",
    scandata        => "$testsdir/scandata.rwf",
    sips004         => "$testsdir/sips-004-008.rw",

    v4set1          => "$testsdir/set1-v4.set",
    v4set2          => "$testsdir/set2-v4.set",
    v4set3          => "$testsdir/set3-v4.set",
    v4set4          => "$testsdir/set4-v4.set",
    v6set1          => "$testsdir/set1-v6.set",
    v6set2          => "$testsdir/set2-v6.set",
    v6set3          => "$testsdir/set3-v6.set",
    v6set4          => "$testsdir/set4-v6.set",

    v4bag1          => "$testsdir/bag1-v4.bag",
    v4bag2          => "$testsdir/bag2-v4.bag",
    v4bag3          => "$testsdir/bag3-v4.bag",
    v6bag1          => "$testsdir/bag1-v6.bag",
    v6bag2          => "$testsdir/bag2-v6.bag",
    v6bag3          => "$testsdir/bag3-v6.bag",

    address_types   => "$testsdir/address_types.pmap",
    fake_cc         => "$testsdir/fake-cc.pmap",
    v6_fake_cc      => "$testsdir/fake-cc-v6.pmap",
    ip_map          => "$testsdir/ip-map.pmap",
    v6_ip_map       => "$testsdir/ip-map-v6.pmap",
    proto_port_map  => "$testsdir/proto-port-map.pmap",

    pysilk_plugin   => "$top_srcdir/tests/pysilk-plugin.py",

    pdu_small       => "$testsdir/small.pdu",
);


#  $path = get_datafile('key')
#
#    Return the path to the data file named by 'key'.  If $key is
#    invalid or if the file does not exist, return undef.
#
sub get_datafile
{
    my ($arg) = @_;

    my $file = $test_files{$arg};
    unless (defined $file) {
        return undef;
    }
    unless (-f $file) {
        return undef;
    }
    return $file;
}


#  $path = get_data_or_exit77('key');
#
#    Like get_datafile(), but exits the program with code 77 if the
#    file does not exist.  This would cause "make check" to skip the
#    test.
#
sub get_data_or_exit77
{
    my ($arg) = @_;

    my $file = get_datafile($arg);
    if (!$file) {
        skip_test("Did not find '$arg' file");
    }
    return $file;
}


#  $env = dump_env();
#
#    Return a string specifying any environment variables that may
#    affect this run
#
sub dump_env
{
    join " ", ((map {"$_=$ENV{$_}"}
                grep {defined $ENV{$_}}
                @DUMP_ENVVARS),
               "");
}


#  $string = print_command_with_env($cmd);
#
#    For verbose debugging, print the bash command that would run
#    '$cmd' in a subshell with all the appropriate environment
#    variables set in the subshell.
#
sub print_command_with_env
{
    my ($cmd) = @_;

    return "( export ".dump_env()." ; ".$cmd." )";
}


#  skip_test($msg);
#
#    Print a message indicating that the test is being skipped due to
#    '$msg' and then exit with status 77.
#
sub skip_test
{
    my ($msg) = @_;
    if ($ENV{SK_TESTS_VERBOSE}) {
        if (!$msg) {
            warn "$NAME: Skipping test\n";
        }
        else {
            warn "$NAME: Skipping test: $msg\n";
        }
    }
    exit 77;
}


#  $dir = make_tempdir();
#
#    Make a temporary directory and return its location.  This will
#    remove the directory on exit unless the appropriate environment
#    variable is set.
#
#    If a temporary directory cannot be created, exit with status 77.
#
sub make_tempdir
{
    my $tmpdir = File::Temp::tempdir(CLEANUP => !$ENV{SK_TESTS_SAVEOUTPUT});
    unless (-d $tmpdir) {
        skip_test("Unable to create temporary directory");
    }

    my $testing = "$tmpdir/-silktests-";
    open TESTING, '>', $testing
        or die "$NAME: Cannot create '$testing': $!\n";
    print TESTING "\$0 = '$0';\n\$PWD = '$SiLKTests::PWD';\n";
    close TESTING
        or die "$NAME: Cannot close '$testing': $!\n";

    return $tmpdir;
}


#  $path = make_tempname($key);
#
#    Return a path to a temporary file.  Calls to this function with
#    the same $key return the same name.  Calls to this function
#    within the same test return files in the same temporary
#    directory.
#
sub make_tempname
{
    my ($key) = @_;

    our $tmpdir;
    our %TEMP_MAP;

    unless (defined $tmpdir) {
        $tmpdir = make_tempdir();
    }

    # change anything other than -, _, ., and alpha-numerics to a
    # single underscore
    $key =~ tr/-_.0-9A-Za-z/_/cs;

    unless (exists $TEMP_MAP{$key}) {
        $TEMP_MAP{$key} = "$tmpdir/$key";
    }
    return $TEMP_MAP{$key};
}


#  run_command($cmd, $callback);
#
#    Run $cmd in a subshell.  $callback should be a function that
#    takes two arguments.  The first argument is a file handle from
#    which the standard output of the $cmd can be read.
#
#    The second argument may be undefined.  If it is defined, the
#    SK_TESTS_SAVEOUTPUT environment variable is set, and the argument
#    contains the name of the (unopened) file to which results should
#    be written.  The individual test can determine which data to
#    write to this file.
#
#    This function returns 0.
#
sub run_command
{
    my ($cmd, $callback) = @_;

    my $save_file;
    if ($ENV{SK_TESTS_SAVEOUTPUT}) {
        $save_file = "tests/$NAME.saveoutput";
    }

    if ($ENV{SK_TESTS_VERBOSE}) {
        print STDERR "RUNNING: ", print_command_with_env($cmd), "\n";
    }
    my $io;
    unless (open $io, "$cmd |") {
        die "$NAME: cannot run '$cmd': $!\n";
    }
    binmode($io);
    $callback->($io, $save_file);
    return 0;
}


#  $ok = compute_md5(\$md5, $cmd, $expect_err);
#
#    Run $cmd in a subshell, compute the MD5 of the output, and store
#    the hex-encoded MD5 in $md5.  Dies if $cmd cannot be run.  If
#    $expect_err is false, function dies if the command exits
#    abnormally.  If $expect_err is true, function dies if command
#    exits normally.
#
sub compute_md5
{
    my ($md5_out, $cmd, $expect_err) = @_;

    # make certain $expect_err has a value
    unless (defined $expect_err) {
        $expect_err = 0;
    }

    if ($ENV{SK_TESTS_VERBOSE}) {
        print STDERR "RUNNING: ", print_command_with_env($cmd), "\n";
    }
    my $md5 = Digest::MD5->new;
    my $io;
    unless (open $io, "$cmd |") {
        die "$NAME: cannot run '$cmd': $!\n";
    }
    binmode($io);
    if (!$ENV{SK_TESTS_SAVEOUTPUT}) {
        $md5->addfile($io);
    } else {
        my $txt = "tests/$NAME.saveoutput";
        open TXT, ">$txt"
            or die "$NAME: Cannot open output file '$txt': $!\n";
        binmode TXT;
        while(<$io>) {
            print TXT;
            $md5->add($_);
        }
        close TXT
            or die "$NAME: Cannot close file '$txt': $!\n";
    }
    if (close($io)) {
        # Close was successful
        if ($expect_err) {
            die "$NAME: Command exited cleanly when error was expected\n";
        }
    }
    elsif (!$expect_err) {
        if ($!) {
            die "$NAME: Error closing command pipe: $!\n";
        }
        if ($? & 127) {
            warn "$NAME: Command died by signal ", ($? & 127), "\n";
        }
        elsif ($?) {
            die ("$NAME: Command exited with non-zero exit status ",
                 ($? >> 8), "\n");
        }
    }
    else {
        # Error was expected
        if ($!) {
            die "$NAME: Error closing command pipe: $!\n";
        }
        if ($? & 127) {
            warn "$NAME: Command died by signal ", ($? & 127), "\n";
        }
        elsif ($ENV{SK_TESTS_VERBOSE}) {
            print STDERR "$NAME: Command exited with status ", ($? >> 8), "\n";
        }
    }
    $$md5_out = $md5->hexdigest;
    return 0;
}


#  check_md5_output($expect_md5, $cmd, $expect_err);
#
#    Die if the MD5 of the output from running $cmd does not equal
#    $expect_md5.  $cmd and $expect_err are passed through to
#    compute_md5().
#
sub check_md5_output
{
    my ($expect, $cmd, $expect_err) = (@_);

    my $md5;
    my $err = compute_md5(\$md5, $cmd, $expect_err);
    if ($expect ne $md5) {
        unless ($ENV{SK_TESTS_VERBOSE}) {
            print STDERR "RUNNING: ", print_command_with_env($cmd), "\n";
        }
        die "$NAME: checksum mismatch [$md5] (expected $expect)\n";
    }
}


#  $ok = compute_md5_file($out_md5, $file);
#
#    Compute the MD5 checksum of $file and set the referent of
#    $out_md5 to the hexdigest value.  Die if the file cannot be opened.
#
sub compute_md5_file
{
    my ($md5_out, $file) = @_;

    my $md5 = Digest::MD5->new;
    my $io;
    unless (open $io, '<', $file) {
        die "$NAME: cannot open '$file': $!\n";
    }
    binmode($io);
    $md5->addfile($io);
    close($io);

    $$md5_out = $md5->hexdigest;
    return 0;
}


#  $ok = check_md5_file($expect_md5, $file);
#
#    Compute the MD5 checksum of $file and compare it to the value in
#    $expect_md5.  Die if the values are not identical.
#
sub check_md5_file
{
    my ($expect, $file) = @_;

    my $md5_hex;
    compute_md5_file(\$md5_hex, $file);

    if ($expect ne $md5_hex) {
        die "$NAME: checksum mismatch [$md5_hex] ($file)\n";
    }
    return 0;
}


#  $app = check_silk_app($name)
#
#    Find the SiLK application named $name and return a path to it.
#
#    If an environment variable exists whose name is the uppercase
#    version of $name, that value is immediately returned.  In all
#    other cases, assuming the application is found, the value
#    returned depends on whether the SK_TESTS_VALGRIND environment
#    variable is set.
#
#    If the executable exists in the current directory, that
#    executable is used.  Otherwise, the subroutine looks for the
#    executable $name in "../$name/$name", where the directory name
#    may be altered depending on $name.
#
#    Exit with status 77 if the application does not exist.
#
#    If SK_TESTS_VALGRIND is not set, return the application name.
#
#    If SK_TESTS_VALGRIND is set, return a command that will run
#    valgrind on the application.  Note that the valgrind program and
#    the arguments to valgrind (with the exception of --log-file) must
#    be set in the SK_TESTS_VALGRIND environment variable.  The script
#    will instruct valgrind to write to a log file based on the name
#    of the script, the application being invoked, and the process ID.
#
#    When SK_TESTS_VALGRIND is set, an environment variable
#    corresponding to the application name is set so that other
#    applications (e.g., rwscanquery, the python daemon wrappers) will
#    run the application under valgrind.
#
sub check_silk_app
{
    my ($name) = @_;

    # create name of environment variable by upcasing the application
    # name and changing hyphens to underscores
    my $envar = "\U$name";
    $envar =~ s/-/_/g;
    if ($ENV{$envar}) {
        return $ENV{$envar};
    }

    my $path = "../$name/$name";
    if (-x $name) {
        $path = "./$name";
    }
    elsif ($name =~ /^rwuniq$/) {
        $path = "../rwstats/$name";
    }
    elsif ($name =~ /^(rwset|rwbag|rwids|rwipa|rwpmap|rwscan)/) {
        $path = "../$1/$name";
    }
    elsif ($name =~ /^rwfglob$/) {
        $path = "../rwfilter/$name";
    }
    elsif ($name =~ /^rwipfix2silk$/) {
        $path = "../rwipfix/$name";
    }
    elsif ($name =~ /^rwsilk2ipfix$/) {
        $path = "../rwipfix/$name";
    }
    elsif ($name =~ /^rwdedupe$/) {
        $path = "../rwsort/$name";
    }

    unless (-x $path) {
        skip_test("Did not find application './$name' or '$path'");
    }
    unless ($ENV{SK_TESTS_VALGRIND}) {
        return $path;
    }

    # set environment variables to have glib work with valgrind
    if (!$ENV{G_SLICE}) {
        $ENV{G_SLICE} = 'always-malloc';
    }
    if (!$ENV{G_DEBUG}) {
        $ENV{G_DEBUG} = 'gc-friendly';
    }

    # determine whether to run the application under libtool by
    # looking for the application as ".libs/$app" or ".libs/lt-$app"
    my $libtool = "";
    my $binary_path = $path;
    $binary_path =~ s,(.*/),$1/.libs/,;
    if (-x $binary_path) {
        $libtool = "$top_builddir/libtool --mode=execute ";
    }
    else {
        $binary_path =~ s,(\.libs)/,$1/lt-,;
        if (-x $binary_path) {
            $libtool = "$top_builddir/libtool --mode=execute ";
        }
    }
    my $log_file = "$NAME.$name.\%p.vg";
    if (-d "tests") {
        $log_file = "tests/$log_file";
    }
    my $valgrind_cmd = ("$libtool$ENV{SK_TESTS_VALGRIND}"
                        ." --log-file=$log_file $path");
    $ENV{$envar} = $valgrind_cmd;
    return $valgrind_cmd;
}


#  check_features(@list)
#
#    Check features of SiLK or of the current run-time environemnt.
#
#    Check whether SiLK was compiled with support for each of the
#    features in '@list' and check whether the run-time environment
#    exhibits the specified features.  If any feature in @list is not
#    present, exit with status 77.
#
#    The acceptable names for '@list' w.r.t. SiLK are:
#
#    gnutls    -- verify that GnuTLS support is available
#    ipa       -- verify that support for libipa is available
#    ipfix     -- verify that IPFIX support is available
#    inet6     -- verify that IPv6 networking support is available
#    ipset_v6  -- verify that IPv6 IPsets is available
#    ipv6      -- verify that IPv6 Flow record support is available
#    netflow9  -- verify that support for NetFlow V9 is available
#
#    The acceptable names for '@list' w.r.t. the environment are:
#
#    stdin_tty -- verify that STDIN is a tty
#
#    If any other name is provided, exit with an error.
#
#    TODO: Idea for an extension, which we currently do not need:
#    Preceding a feature name with '!' causes the script to exit with
#    status 77 if the feature IS present.
#
sub check_features
{
    my (@list) = @_;

    our %feature_hash;

    for my $feature (@list) {
        my $check = $feature_hash{$feature};
        if (!$check) {
            die "$NAME: No such feature as '$feature'\n";
        }
        $check->();
    }
}


#  check_app_switch($app, $switch, $re)
#
#    Check the output of the --help switch.  This function invokes
#    "$app --help" and captures the output.  '$app' should be the
#    application name, and it may include switches.  The function
#    searches the output for the switch '--$switch'.  If '$re' is
#    undefined, the function returns true if the switch is found.
#    When '$re' is defined, the help text of the switch is regex
#    matched with '$re', and the result of the match is returned.
#
#    The function returns false if the running the application fails.
#
sub check_app_switch
{
    my ($app, $switch, $re) = @_;

    my $cmd = $app.' --help 2>&1';
    if ($ENV{SK_TESTS_VERBOSE}) {
        print STDERR "RUNNING: ", print_command_with_env($cmd), "\n";
    }
    my $output = `$cmd`;
    if ($?) {
        if (-1 == $?) {
            die "$NAME: Failed to execute command: $!\n";
        }
        if ($? & 127) {
            print STDERR "$NAME: Command died by signal ", ($? & 127), "\n";
        }
        elsif ($ENV{SK_TESTS_VERBOSE}) {
            print STDERR "$NAME: Command exited with status ", ($? >> 8), "\n";
        }
        return 0;
    }
    my $text;
    if ($output =~ m/^(--$switch[^-\w].*(\n[^-].+)*)/m) {
        $text = $1;
        unless (defined $re) {
            return 1;
        }
        if ($text =~ $re) {
            return 1;
        }
    }
    return 0;
}


#  check_daemon_init_program_name($init_script, $daemon_name);
#
#    Verify that the daemon start-up script '$init_script' (for
#    example, rwflowpack.init.d) starts the daemon we expect it to,
#    namely '$daemon_name' ('rwflowpack' in our example).
#
#    The purpose of this function is to skip these tests when the user
#    has used the --program-prefix/--program-suffix switches to
#    configure.  The issue is that the $init_script contains the
#    modified daemon name, but the name only is modified at
#    installation time.
#
#    This function ensures the 'MYNAME' and 'PROG' variables in shell
#    script $init_script are set to $daemon_name.  If it does not, the
#    test is skipped.
#
sub check_daemon_init_program_name
{
    my ($init_script, $daemon_name) = @_;

    open INIT, $init_script
        or die "$NAME: Unable to read start-up script '$init_script': $!\n";
    while (<INIT>) {
        chomp;
        if (/^(MYNAME|PROG)=(\S+)\s*$/) {
            if ($2 ne $daemon_name) {
                skip_test("Start-up script '$init_script' on line $."
                          ." does not use expected daemon name '$daemon_name';"
                          ." instead found '$_'");
            }
        }
    }
    close INIT;
}


#  check_exit_status($cmd, $no_redirect)
#
#    Run $cmd.  Return 1 if the command succeeded, or 0 if it failed.
#
#    If $no_redirect is true, do not redirect the stdout or stderr of
#    $cmd in any way (meaning it should be written to the "make check"
#    log file.
#
#    If $no_redirect is false (or not defined) and the SK_TESTS_SAVEOUTPUT
#    environment varialbe is not set, discard stdout and stderr.
#
#    If $no_redirect is false (or not defined) and the
#    SK_TESTS_SAVEOUTPUT environment variable is set, write the output
#    to the file "tests/$NAME.saveoutput".
#
sub check_exit_status
{
    my ($cmd, $no_redirect) = @_;

    if ($ENV{SK_TESTS_VERBOSE}) {
        print STDERR "RUNNING: ", print_command_with_env($cmd), "\n";
    }

    unless ($no_redirect) {
        # where to write the output
        my $output = "/dev/null";

        if ($ENV{SK_TESTS_SAVEOUTPUT}) {
            $output = "tests/$NAME.saveoutput";
        }
        $cmd .= " >$output 2>&1";
    }

    system $cmd;
    if (0 == $?) {
        return 1;
    }
    if (-1 == $?) {
        die "$NAME: Failed to execute command: $!\n";
    }
    if ($? & 127) {
        print STDERR "$NAME: Command died by signal ", ($? & 127), "\n";
    }
    elsif ($ENV{SK_TESTS_VERBOSE}) {
        print STDERR "$NAME: Command exited with status ", ($? >> 8), "\n";
    }
    return 0;
}


#  check_python_bin()
#
#    Check whether we found a python interpreter.  If we did not,
#    exit 77.  Otherwise, prefix any existing PYTHONPATH with the
#    proper directories and return 1.
#
#    This check used by the code that tests daemons since the daemon
#    testing code requires a python interpreter.
#
sub check_python_bin
{
    if ($SiLKTests::PYTHON eq "no"
        || $SiLKTests::PYTHON_VERSION !~ /^[23]/
        || $SiLKTests::PYTHON_VERSION =~ /^2.[45]/)
    {
        skip_test("Python unset or not >= 2.6 < 4.0");
    }
    $ENV{PYTHONPATH} = join ":", ($SiLKTests::top_builddir.'/tests',
                                  $SiLKTests::srcdir.'/tests',
                                  $SiLKTests::top_srcdir.'/tests',
                                  ($ENV{PYTHONPATH} ? $ENV{PYTHONPATH} : ()));
    return 1;
}


#  check_python_plugin($app)
#
#    Check whether the --python-file switch works for the application
#    $app.  The argument to --python-file is the pysilk_plugin defined
#    in the %test_files hash.  If the switch does not work, exit 77.
#
sub check_python_plugin
{
    my ($app) = @_;

    my $file = get_data_or_exit77('pysilk_plugin');
    if (check_exit_status(qq|$app --python-file=$file --help|)) {
        return;
    }
    check_exit_status(qq|$app --python-file=$file --help|, 'no_redirect');
    skip_test('Cannot use --python-file');
}


#  add_plugin_dirs(@libs)
#
#    For each directory in @libs, prefix the directory name and the
#    directory name with "/.libs" appended to it to the
#    LD_LIBRARY_PATH (and platform variations of that environment
#    variable).
#
#    Each directory in @libs should relative to the top of the build
#    tree.
#
sub add_plugin_dirs
{
    my (@dirs) = (@_);

    my $newlibs = join (":",
                        map {"$_:$_/.libs"}
                        map {"$SiLKTests::top_builddir$_"}
                        @dirs);
    for my $L (qw(LD_LIBRARY_PATH DYLD_LIBRARY_PATH LIBPATH SHLIB_PATH)) {
        if ($ENV{$L}) {
            $ENV{$L} = $newlibs.":".$ENV{$L};
        }
        else {
            $ENV{$L} = $newlibs;
        }
    }
}


#  $port = get_ephemeral_port($host, $proto);
#
#    Get an ephemeral port by creating a short-lived server listening
#    on the specified $host and $protocol, and using the fact that
#    binding to port 0 assigns an available ephemeral port.
#
#    If the short-lived server cannot be created, the program exits
#    with status 77.
#
sub get_ephemeral_port
{
    use Socket ();

    my ($host, $proto) = @_;
    my $type = Socket::SOCK_DGRAM;

    unless ($host) {
        $host = '127.0.0.1';
    }
    unless ($proto) {
        $proto = getprotobyname('tcp');
        $type = Socket::SOCK_STREAM;
    }
    else {
        if ($proto =~ /\D/) {
            $proto = getprotobyname($proto);
        }
        if (getprotobyname('tcp') == $proto) {
            $type = Socket::SOCK_STREAM;
        }
    }

    if ($host =~ /:/) {
        # IPv6; run in an eval, in case Socket6 is not available.
        my $have_socket6 = 0;

        my $port = eval <<EOF;
        use Socket  qw(SOL_SOCKET SO_REUSEADDR);
        use Socket6 qw(getaddrinfo getnameinfo AF_INET6
                       NI_NUMERICHOST NI_NUMERICSERV);

        \$have_socket6 = 1;

        my (\$s, \$port);
        unless (socket(\$s, AF_INET6, $type, $proto)) {
            skip_test("Unable to open socket: \$!)";
        }
        setsockopt(\$s, SOL_SOCKET, SO_REUSEADDR, 1);

        my \@res = getaddrinfo('$host', 0, AF_INET6, $type, $proto);
        if (\$#res == 0) {
            skip_test("Unable to resolve '$host'");
        }

        my \$s_addr = \$res[3];
        unless (bind(\$s, \$s_addr)) {
            skip_test("Unable to bind to socket: \$!");
        }

        (undef, \$port) = getnameinfo(getsockname(\$s),
                                      (NI_NUMERICHOST | NI_NUMERICSERV));
        close(\$s);

        return \$port;
EOF
        if (defined $port) {
            return $port;
        }
        if ($@ && $have_socket6) {
            skip_test("$@");
        }
        # Assume failure was due to absence of Socket6 module, and use
        # IPv4 to get a port
        $host = '127.0.0.1';
    }

    # IPv4

    my ($s, $port);
    unless (socket($s, Socket::PF_INET, $type, $proto)) {
        skip_test("Unable to open socket: $!");
    }
    setsockopt($s, Socket::SOL_SOCKET, Socket::SO_REUSEADDR, 1);

    my $h_addr = Socket::inet_aton($host);
    unless (defined $h_addr) {
        skip_test("Unable to resolve '$host'");
    }
    my $s_addr = Socket::sockaddr_in(0, $h_addr);

    unless (bind($s, $s_addr)) {
        skip_test("Unable to bind to socket: $!");
    }

    ($port, ) = Socket::sockaddr_in(getsockname($s));
    close($s);

    return $port;

    # The following does the same as the above
    #
    # my $s = IO::Socket::INET->new(Proto =>     $proto,
    #                               LocalAddr => $host,
    #                               LocalPort=>  0,
    #                               Reuse =>     1,
    #     );
    # unless ($s) {
    #     if ($ENV{SK_TESTS_VERBOSE}) {
    #         warn "$NAME: Cannot create $proto server on $host: $!\n";
    #     }
    #     exit 77;
    # }
    # my $port = $s->sockport;
    # $s->close();
    #
    # return $port;
}


#  rwpollexec_use_alternate_shell($tmpdir)
#
#    Work around an issue that occurs when running "make check" under
#    OS X when System Integrity Protection is enabled.
#
#    As part of finding a valid shell to use when spawning programs,
#    rwpollexec attempts to exec itself in a subshell.(NOTE-1)  This
#    subprocess does not have access to the DYLD_LIBRARY_PATH
#    environment variable since /bin/sh strips it from the
#    environment, and therefore rwpollexec fails to run since it
#    cannot locate libsilk.
#
#    The work-around is to copy /bin/sh out of the /bin directory and
#    set SILK_RWPOLLEXEC_SHELL to that location.(NOTE-2) This function
#    copies it into the $tmpdir.
#
#    NOTE-1: This is only a problem when running a non-installed
#    version of rwpollexec.  In this case, rwpollexec thinks its
#    complete path is in the .libs subdirectory, but that version
#    requires DYLD_LIBRARY_PATH settings from libtool to work
#    correctly.
#
#    NOTE-2: Copying /bin/sh to another directory works around the
#    issue since stripping DYLD_LIBRARY_PATH from the environment
#    occurs for all programs in /bin and is not inherent to /bin/sh
#    itself.
#
sub rwpollexec_use_alternate_shell
{
    my ($dir) = @_;

    my $bin_sh = '/bin/sh';
    my $copy_sh = "$dir/sh";

    for my $shell ($bin_sh, $copy_sh) {
        # Fork, set the DYLD_LIBRARY_PATH environment variable in the
        # child, and then exec $shell and echo the envvar's value.
        # Have the parent read the output from the child.  Do not use
        # backticks, since that may run /bin/sh for us.
        my $pid = open ECHO, '-|';
        if (!defined $pid) {
            die "$NAME: Cannot fork: $!\n";
        }
        if (0 == $pid) {
            # Child
            $ENV{DYLD_LIBRARY_PATH} = "foo";
            #print STDERR "\$i = $i; $shell -c 'echo \$DYLD_LIBRARY_PATH'\n";
            exec $shell, '-c', 'echo $DYLD_LIBRARY_PATH'
                or die "$NAME: Cannot exec: $!\n";
        }
        # Parent
        my $result = '';
        while (<ECHO>) {
            $result .= $_;
        }
        close(ECHO);
        #print STDERR "\$i = $i; \$result = '$result'\n";

        if ($result =~ /^foo$/) {
            # Either System Integrity Protection is not enabled or we
            # worked around it
            return;
        }
        if ($shell eq $copy_sh) {
            # This is the second pass and we failed to work around it;
            # should skip this test.
            skip_test("Unable to work around OS X System Integrity Protection");
        }

        unless (-d $dir) {
            die "$NAME: Directory '$dir' does not exist\n";
        }
        system '/bin/cp', $bin_sh, $copy_sh
            and die "$NAME: Unable to copy $bin_sh\n";

        $ENV{SILK_RWPOLLEXEC_SHELL} = $copy_sh;
        push @DUMP_ENVVARS, 'SILK_RWPOLLEXEC_SHELL';
    }
    die "$NAME: Not reached!\n";
}


#  santize_cmd(\$cmd);
#
#    Remove any references to the source path or to the temporary
#    directory from '$cmd' prior to $cmd into the top of the source
#    file
#
sub sanitize_cmd
{
    my ($cmd) = @_;

    # don't put source path into test file
    $$cmd =~ s,\Q$top_srcdir,$top_builddir,g;

    # don't put TMPDIR into test file
    my $tmp = $ENV{TMPDIR} || '/tmp';

    # convert "$TMPDIR/foobar/file" to "/tmp/file"
    $$cmd =~ s,\Q$tmp\E/?(\S+/)*,/tmp/,g;
}


#  verify_archived_files($archive_base, @file_list);
#
#    Verify that the files in @file_list exist in subdirectories of
#    '$archive_base', where the subdirectory is based on the current
#    UTC time in the form YYYY/MM/DD/hh/.
#
#    See also verify_directory_files().
#
#    Any directory components of the elements in @file_list will be
#    removed.  That is, only the basename of the files in @file_list
#    are considered.
#
#    Since it is possible for the hour to roll-over during a test, the
#    function checks subdirectories based on the current time and on
#    the time when the Perl script began running (given by the $^T
#    variable).
#
#    Exit with an error if the $archive_base does not exist.
#
#    Exit with an error if any of the files do not exist.
#
sub verify_archived_files
{
    my ($archive_base, @file_list) = @_;

    unless (-d $archive_base) {
        die "$NAME: Directory '$archive_base' does not exist\n";
    }

    # remove trailing slash and any double slashes
    $archive_base =~ s,/+$,,g;
    $archive_base =~ s,//+,/,g;

    # take basename of the expected files and create a hash
    my %expected_files;
    for my $f (@file_list) {
        $f =~ s,.*/,,;
        $expected_files{$f} = "'$archive_base/.../$f'";
    }

    # generate expected directories based on timestamps
    my %expected_dirs;
    $expected_dirs{$archive_base} = $archive_base;

    for my $ts ($^T, time) {
        # generate components of potential archive directory
        my @t = gmtime($ts);
        my @parts = (sprintf("%4d",   (1900 + $t[5])),
                     sprintf("%02d",  (1 + $t[4])),
                     sprintf("%02d",  $t[3]),
                     sprintf("%02d",  $t[2]),
            );
        for (my $i = 0; $i < @parts; ++$i) {
            my $d = join "/", $archive_base, @parts[0..$i];
            $expected_dirs{$d} = "'$d'";
        }
    }

    my @unexpected;

    use File::Find qw//;
    File::Find::find(
        sub {
            lstat $_;
            if ((-d _) && $expected_dirs{$File::Find::name}) {
                return;
            }
            if ((-f _)
                && $expected_files{$_} && $expected_dirs{$File::Find::dir})
            {
                delete $expected_files{$_};
                return;
            }
            push @unexpected, "'$File::Find::name'";
        },
        $archive_base);


    if (keys %expected_files) {
        my @missing = values %expected_files;
        if (@unexpected) {
            die ("$NAME: Missing file", ((@missing > 1) ? "s " : " "),
                 join(", ", @missing), " and found unexpected ",
                 ((@unexpected > 1) ? "entries " : "entry "),
                 join(", ", @unexpected), "\n");
        }
        die ("$NAME: Missing file", ((@missing > 1) ? "s " : " "),
             join(", ", @missing), "\n");
    }
    if (@unexpected) {
        die ("$NAME: Found unexpected ",
             ((@unexpected > 1) ? "entries " : "entry "),
             join(", ", @unexpected), "\n");
    }
}


#  verify_directory_files($dir, @file_list);
#
#    Verify that the files in @file_list exist in the directory
#    '$dir' and verify that no other files exist in the directory.
#
#    Any directory components of the elements in @file_list will be
#    removed.  That is, only the basename of the files in @file_list
#    are considered.
#
#    Exit with an error if the $dir does not exist, if any of the
#    files do not exist, or if any other files are found.
#
sub verify_directory_files
{
    my ($dir, @file_list) = @_;

    # table of expected files
    my %expected;
    for my $f (@file_list) {
        # take basename
        $f =~ s,.*/,,;
        $expected{$f} = "'$dir/$f'";
    }

    my @unexpected;

    unless (opendir D, $dir) {
        die "$NAME: Cannot open directory '$dir': $!\n";
    }
    while (defined(my $f = readdir(D))) {
        next if $f =~ /^\.\.?$/;
        if ($expected{$f}) {
            delete $expected{$f};
        }
        else {
            push @unexpected, "'$dir/$f'";
        }
    }
    closedir D;

    if (keys %expected) {
        my @missing = values %expected;
        if (@unexpected) {
            die ("$NAME: Missing file", ((@missing > 1) ? "s " : " "),
                 join(", ", @missing),
                 " and found unexpected file",((@unexpected > 1) ? "s " : " "),
                 join(", ", @unexpected), "\n");
        }
        die ("$NAME: Missing file", ((@missing > 1) ? "s " : " "),
             join(", ", @missing), "\n");
    }
    if (@unexpected) {
        die ("$NAME: Found unexpected file", ((@unexpected > 1) ? "s " : " "),
             join(", ", @unexpected), "\n");
    }
}


#  verify_empty_dirs($base_dir, @dir_list)
#
#    For each string in @dir_list, if the string begins with a slash
#    (/), use it as is.  If the string does not begin with a slash and
#    $base_dir is defined, prepend the string "$base_dir/" to the
#    string.
#
#    For each of the (possibly modified) strings, see if a directory
#    exists with that name.  If so, verify that no files exist that
#    directory.
#
#    Exit with an error if any directories are not empty.
#
sub verify_empty_dirs
{
    my ($base_dir, @dir_list) = @_;

    my @unexpected;

    if (defined $base_dir) {
        for my $d (@dir_list) {
            unless ($d =~ m,^/,) {
                $d = $base_dir.'/'.$d;
            }
        }
    }
    for my $d (@dir_list) {
        unless (-d $d) {
            warn "$NAME: Entry '$d' exists but is not a directory\n"
                if -e $d;
            next;
        }
        unless (opendir D, $d) {
            warn "$NAME: Cannot open directory '$d': $!\n";
            next;
        }
        while (my $f = readdir(D)) {
            next if $f =~ /^\.\.?$/;
            push @unexpected, "'$d/$f'";
        }
        closedir D;
    }

    if (@unexpected) {
        die "$NAME: Found unexpected file", ((@unexpected > 1) ? "s " : " "),
            join(", ", @unexpected), "\n";
    }
}


sub make_test_scripts
{
    my ($APP, $test_tuples, $tests_list_hash) = @_;

    my @temp_param = ('make-tests-XXXXXXXX',
                      UNLINK => 1,
                      DIR => File::Spec->tmpdir);

    if ($ENV{SK_TESTS_SAVEOUTPUT}) {
        $File::Temp::KEEP_ALL = 1;
    }

    # get the path to the application
    my $APP_PATH;
    if ($APP =~ m,/,) {
        $APP_PATH = $APP;
        $APP =~ s,.*/,,;
    }
    else {
        $APP_PATH = "./$APP";
    }

    # variable that holds the name of the application for use in the
    # script; this variable includes the leading "$".
    my $APP_VARNAME = '$'.$APP;
    $APP_VARNAME =~ s/-/_/g;

    my @test_list;
    my @xfail_list;

    our (%global_tests);

  TUPLE:
    while (defined(my $tuple = shift @$test_tuples)) {
        # first two arguments in tuple are positional
        my $test_name = shift @$tuple;
        my $test_type = shift @$tuple;

        # print the name of the file to create; this can be
        # over-ridden if the test-tuple contains a -testfile value
        my $outfile = "$APP-$test_name.pl";
        print "Creating $outfile\n";

        # others are in tuple are by keyword
        my ($file_keys, $app_keys, $env_hash, $lib_list, $temp_keys,
            $feature_list, $exit77, $pretest, @cmd_list);
        while (defined (my $k = shift @$tuple)) {
            if ($k =~ /^-files?/) {
                $file_keys = shift @$tuple;
            }
            elsif ($k =~ /^-apps?/) {
                $app_keys  = shift @$tuple;
            }
            elsif ($k =~ /^-env/) {
                $env_hash  = shift @$tuple;
            }
            elsif ($k =~ /^-libs?/) {
                $lib_list  = shift @$tuple;
            }
            elsif ($k =~ /^-temps?/) {
                $temp_keys = shift @$tuple;
            }
            elsif ($k =~ /^-cmds?/) {
                my $tmp = shift @$tuple;
                if ('ARRAY' eq ref($tmp)) {
                    @cmd_list = @$tmp;
                } else {
                    @cmd_list = ($tmp);
                }
            }
            elsif ($k =~ /^-features?/) {
                $feature_list = shift @$tuple;
            }
            elsif ($k =~ /^-exit77/) {
                $exit77 = shift @$tuple;
            }
            elsif ($k =~ /^-pretest/) {
                $pretest = shift @$tuple;
            }
            elsif ($k =~ /^-testfile$/) {
                $outfile = shift @$tuple;
            }
            elsif ($k =~ /^-/) {
                croak "$NAME: Unknown tuple key '$k'";
            }
            else {
                croak "$NAME: Expected to find key in tuple";
            }
        }

        # add file to create to our output list
        $outfile = "tests/$outfile";
        push @test_list, $outfile;
        $outfile = "$srcdir/$outfile";

        if ($global_tests{$outfile}) {
            carp "\nWARNING!! Duplicate test '$outfile'\n";
        }
        $global_tests{$outfile} = 1;

        # the body of the test file we are writing
        my $test_body = <<EOF;
#! /usr/bin/perl -w
#HEADER
use strict;
use SiLKTests;

my $APP_VARNAME = check_silk_app('$APP');
EOF

        # the body of the string we eval to get the test command
        my $run_body = "my $APP_VARNAME = '$APP_PATH';\n";

        # handle any required applications
        if ($app_keys && @$app_keys) {
            for my $key (@$app_keys) {
                my $app = check_silk_app($key);
                if (!$app) {
                    die "$NAME: No app '$app'";
                }
                $run_body .= "my \$$key = '$app';\n";
                $test_body .= "my \$$key = check_silk_app('$key');\n";
            }
        }

        # handle any required data files
        if ($file_keys && @$file_keys) {
            $run_body .= "my \%file;\n";
            $test_body .= "my \%file;\n";
            for my $key (@$file_keys) {
                my $file = get_datafile($key);
                if (!$file) {
                    # Skip V6 when built without V6
                    if ($key eq 'v6data' && $SiLKTests::SK_ENABLE_IPV6 == 0) {
                        warn $INDENT, "Skipping V6 test\n";
                        next TUPLE;
                    }
                    die "$NAME: No file '$key'";
                }
                $run_body .= "\$file{$key} = '$file';\n";
                $test_body .= "\$file{$key} = get_data_or_exit77('$key');\n";
            }
        }

        # handle any necessary temporary files
        if ($temp_keys && @$temp_keys) {
            $run_body .= "my \%temp;\n";
            $test_body .= "my \%temp;\n";
            for my $key (@$temp_keys) {
                my $temp = make_tempname("$APP-$test_name-$key");
                if (!$temp) {
                    die "$NAME: No temp '$APP-$test_name-$key'";
                }
                # make certain to start with a clean slate
                unlink $temp;
                $run_body .= "\$temp{$key} = '$temp';\n";
                $test_body .= "\$temp{$key} = make_tempname('$key');\n";
            }
        }

        # Set any environment variables
        if ($env_hash) {
            for my $var (sort keys %$env_hash) {
                my $val = $env_hash->{$var};
                $test_body .= "\$ENV{$var} = $val;\n";
                $run_body .= "\$ENV{$var} = $val;\n";
            }
        }

        # Set the LD_LIBRARY_PATH
        if ($lib_list) {
            my $new_libs = join ", ", map {"'/$_'"} @$lib_list;
            my $libs_expr .= <<EOF;
add_plugin_dirs($new_libs);
EOF

            $test_body .= $libs_expr;
            $run_body .= $libs_expr;
        }

        # Add feature checks
        if ($feature_list && @$feature_list) {
            $test_body .= <<EOF;
check_features(qw(@$feature_list));
EOF
        }
        if ($exit77) {
            $test_body .= <<EOF;

exit 77 if sub { $exit77 }->();

EOF
        }

        # add any extra code
        if ($pretest) {
            $run_body .= "\n$pretest\n";
            $test_body .= "\n$pretest\n";
        }

        # This gets filled in by the various test types
        my $header = "\n";

        # run the test, which depends on its type
        if ($test_type == $STATUS) {
            if (@cmd_list > 1) {
                croak "$NAME: Too many commands\n";
            }
            my $cmd = shift @cmd_list;

            my ($fh, $tmp_cmd) = File::Temp::tempfile(@temp_param);

            # make $fh unbuffered
            select((select($fh), $| = 1)[0]);
            print $fh <<EOF;
use strict;
do "$INC{'SiLKTests.pm'}";
import SiLKTests;
$run_body
exec "$cmd"
EOF

            if ($DEBUG_SCRIPTS) {
                print $INDENT, "****\n";
                seek $fh, 0, 0;
                while (defined (my $line = <$fh>)) {
                    print $INDENT, $line;
                }
                print $INDENT, "****\n";
            }

            # the run_body returns the string containing the test to run
            my %OLD_ENV = (%ENV);
            $run_body .= qq/"$cmd"/;
            my $run_cmd = eval "$run_body"
                or croak "ERROR! '$cmd'\n$@";
            %ENV = (%OLD_ENV);

            print $INDENT, "Invoking $run_cmd\n";
            my $status = check_exit_status("perl $tmp_cmd");
            my ($status_str, $exit_conditions);
            if (!$status) {
                $status_str = 'ERR';
                $exit_conditions = '? 1 : 0';
            }
            else {
                $status_str = 'OK';
                $exit_conditions = '? 0 : 1';
            }
            print $INDENT, "[$status_str]\n";

            sanitize_cmd(\$run_cmd);

            # store the test string in the test itself
            $header = <<EOF;
# STATUS: $status_str
# TEST: $run_cmd
EOF

            $test_body .= <<EOF;
my \$cmd = "$cmd";

exit (check_exit_status(\$cmd) $exit_conditions);
EOF
        }

        elsif ($test_type == $MD5 || $test_type == $ERR_MD5) {
            if (@cmd_list > 1) {
                croak "$NAME: Too many commands\n";
            }
            my $cmd = shift @cmd_list;

            my ($fh, $tmp_cmd) = File::Temp::tempfile(@temp_param);

            # make $fh unbuffered
            select((select($fh), $| = 1)[0]);
            print $fh <<EOF;
use strict;
do "$INC{'SiLKTests.pm'}";
import SiLKTests;
$run_body
exec "$cmd"
EOF

            if ($DEBUG_SCRIPTS) {
                print $INDENT, "****\n";
                seek $fh, 0, 0;
                while (defined (my $line = <$fh>)) {
                    print $INDENT, $line;
                }
                print $INDENT, "****\n";
            }

            # the run_body returns the string containing the test to run
            my %OLD_ENV = (%ENV);
            $run_body .= qq/"$cmd"/;
            my $run_cmd = eval "$run_body"
                or croak "ERROR! '$cmd'\n$@";
            %ENV = (%OLD_ENV);

            my $expect_err = "";
            if ($test_type == $ERR_MD5) {
                $expect_err = ", 1";
            }

            my $test_type_str = (($test_type == $MD5) ? "MD5" : "ERR_MD5");

            print $INDENT, "Invoking $run_cmd\n";
            my $md5;
            compute_md5(\$md5, "perl $tmp_cmd", !!$expect_err);
            print $INDENT, "[$md5]\n";

            sanitize_cmd(\$run_cmd);

            # store the test string in the test itself
            $header = <<EOF;
# $test_type_str: $md5
# TEST: $run_cmd
EOF

            $test_body .= <<EOF;
my \$cmd = "$cmd";
my \$md5 = "$md5";

check_md5_output(\$md5, \$cmd$expect_err);
EOF
        }

        elsif ($test_type == $CMP_MD5) {
            my @expanded_cmd = ();

            my $run_body_orig = $run_body;
            for my $cmd (@cmd_list) {

                my ($fh, $tmp_cmd) = File::Temp::tempfile(@temp_param);

                # make $fh unbuffered
                select((select($fh), $| = 1)[0]);
                print $fh <<EOF;
use strict;
do "$INC{'SiLKTests.pm'}";
import SiLKTests;
$run_body_orig
exec "$cmd"
EOF

                if ($DEBUG_SCRIPTS) {
                    print $INDENT, "****\n";
                    seek $fh, 0, 0;
                    while (defined (my $line = <$fh>)) {
                        print $INDENT, $line;
                    }
                    print $INDENT, "****\n";
                }

                my %OLD_ENV = (%ENV);
                $run_body = $run_body_orig . qq/"$cmd"/;
                my $run_cmd = eval "$run_body"
                    or croak "ERROR! '$cmd'\n$@";
                %ENV = (%OLD_ENV);

                print $INDENT, "Invoking $run_cmd\n";
                my $md5;
                compute_md5(\$md5, "perl $tmp_cmd");
                print $INDENT, "[$md5]\n";

                sanitize_cmd(\$run_cmd);

                push @expanded_cmd, $run_cmd;
            }

            $header = join("\n# TEST: ", '# CMP_MD5', @expanded_cmd)."\n";

            my $cmds_string = '"'.join(qq|",\n|.(' 'x12).'"', @cmd_list).'"';

            $test_body .= <<EOF;
my \@cmds = ($cmds_string);
my \$md5_old;

for my \$cmd (\@cmds) {
    my \$md5;
    compute_md5(\\\$md5, \$cmd);
    if (!defined \$md5_old) {
        \$md5_old = \$md5;
    }
    elsif (\$md5_old ne \$md5) {
        die "$APP-$test_name.pl: checksum mismatch [\$md5] (\$cmd)\\n";
    }
}
EOF
        }

        # fill in the header
        $test_body =~ s/^#HEADER/$header/m;

        open OUTFILE, "> $outfile"
            or die "$NAME: open $outfile: $!";
        print OUTFILE $test_body;
        close(OUTFILE)
            or die "$NAME: close $outfile: $!";
    }


    # Tests are complete.  Either put the values into the hash
    # reference that was passed in, or print the values ourselves

    if ('HASH' ne ref($tests_list_hash)) {
        print_tests_hash({TESTS => \@test_list, XFAIL_TESTS => \@xfail_list});
    }
    else {
        if (@test_list) {
            unless (exists $tests_list_hash->{TESTS}) {
                $tests_list_hash->{TESTS} = [];
            }
            push @{$tests_list_hash->{TESTS}}, @test_list;
        }
        if (@xfail_list) {
            unless (exists $tests_list_hash->{XFAIL_TESTS}) {
                $tests_list_hash->{XFAIL_TESTS} = [];
            }
            push @{$tests_list_hash->{XFAIL_TESTS}}, @xfail_list;
        }
    }
}


sub print_tests_hash
{
    my ($tests_list) = @_;

    for my $t (qw(TESTS XFAIL_TESTS)) {
        if (exists($tests_list->{$t}) && @{$tests_list->{$t}}) {
            print "$t = @{$tests_list->{$t}}\n";
        }
    }

    if ($ENV{SK_TESTS_MAKEFILE}) {
        my $makefile = "$srcdir/Makefile.am";
        if (-f $makefile) {
            print "Modifying $makefile\n";

            open MF, ">> $makefile"
                or croak "$NAME: Opening '$makefile' failed: $!";
            print MF "\n# Added by $NAME on ".localtime()."\n";
            for my $t (qw(TESTS XFAIL_TESTS)) {
                if (exists($tests_list->{$t}) && @{$tests_list->{$t}}) {
                    print MF join(" \\\n\t", "$t =", @{$tests_list->{$t}}),"\n";
                }
            }
            close MF
                or croak "$NAME: Closing '$makefile' failed: $!";
        }
    }

    if ($ENV{SK_TESTS_CHECK_MAKEFILE}) {
        my $makefile = "$srcdir/Makefile.am";
        if (-f $makefile) {
            print "Checking $makefile\n";

            my %make_lists = (TESTS => {}, XFAIL_TESTS => {});

            open MF, "$makefile"
                or croak "$NAME: Opening '$makefile' failed: $!";
            my $t;
            while (defined(my $line = <MF>)) {
                if ($line =~ /^(TESTS|XFAIL_TESTS) *= *\\/) {
                    $t = $1;
                    next;
                }
                next unless $t;
                if ($line =~ /^[ \t]*(\S+)(| \\)$/) {
                    $make_lists{$t}{$1} = 1;
                    if (!$2) {
                        $t = undef;
                    }
                }
            }
            close MF;

            for my $t (qw(TESTS XFAIL_TESTS)) {
                my @missing;
                if (exists($tests_list->{$t})) {
                    for my $i (@{$tests_list->{$t}}) {
                        if (!$make_lists{$t}{$i}) {
                            push @missing, $i;
                        }
                        else {
                            delete $make_lists{$t}{$i};
                        }
                    }
                }
                my @extra = keys %{$make_lists{$t}};
                if (@missing) {
                    print "MISSING $t = @missing\n";
                }
                if (@extra) {
                    print "EXTRA $t = @extra\n";
                }
            }
        }
    }
}


#  make_config_file($file, $text_reference)
#
#    Writes the text in the scalar reference '$text_reference' to the
#    file named by '$file'.  In addition, when $ENV{SK_TESTS_VERBOSE}
#    is set, prints the text to the standard error for capture by the
#    Automake test harness.
#
#    Exits the test if the file cannot be opened or written.
#
sub make_config_file
{
    my ($out, $text_ref) = @_;

    open CONFIG, ">", $out
        or die "$NAME: Cannot open file '$out': $!\n";
    print CONFIG $$text_ref;
    close CONFIG
        or die "$NAME: Cannot close file '$out': $!\n";

    if ($ENV{SK_TESTS_VERBOSE}) {
        print STDERR ">> START OF FILE '$out' >>>>>>>>>>\n";
        print STDERR $$text_ref;
        print STDERR "<< END OF FILE '$out' <<<<<<<<<<<<\n";
    }
}


sub make_packer_sensor_conf
{
    my ($sensor_conf, $probe_type, $port, @rest) = @_;

    my $sensor_template = "$srcdir/tests/sensors.conf";

    my %features;

    for my $f (@rest) {
        my $re = "\\#\U$f\\#";
        $features{$f} = qr/$re/;
    }

    my $text = "";

    open SENSOR_IN, $sensor_template
        or die "$NAME: Cannot open file '$sensor_template': $!\n";
    while (defined (my $line = <SENSOR_IN>)) {
        $line =~ s/PROBETYPE/$probe_type/g;
        $line =~ s/RANDOMPORT/$port/g;
        for my $re (values %features) {
            $line =~ s/$re//g;
        }
        $text .= $line;
    }
    close SENSOR_IN;
    make_config_file($sensor_conf, \$text);
}


1;
__END__
