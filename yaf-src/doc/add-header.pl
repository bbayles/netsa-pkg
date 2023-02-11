#! /usr/bin/env perl
#
#  This script modifies the HTML man pages generated by pod2html.  It
#  performs minor clean up and creates links to other man pages.
#

use warnings;
use strict;
use File::Copy  qw//;
use File::Temp  qw//;

# name of this script
my $NAME = $0;
$NAME =~ s,.*/,,;

# Other man pages to link to
my @man_pages = qw(
    airdaemon
    applabel
    filedaemon
    getFlowKeyHash
    yaf
    yaf.init
    yafMeta2Pcap
    yafdhcp
    yafdpi
    yafscii
    yafzcbalance
    );
our $man_re = '('.join('|', map { "\Q$_\E" } @man_pages).')';

our $old = $ARGV[0];
unless ($old) {
    die "Usage: $NAME <filename>\n\tClean HTML in the specified file\n";
}

open(OLD, '<', $old)
    or die "$NAME: Cannot open '$old' for reading: $!\n";

our ($fh, $new) = File::Temp::tempfile(UNLINK => 1)
    or die "$NAME: Unable to create a temporary file: $!\n";
*NEW = $fh;

do_manpage();

close OLD;
close NEW
    or die "$NAME: Cannot close '$new': $!\n";

File::Copy::move $new, $old
    or die "$NAME: Cannot replace '$old' with '$new': $!\n";

exit;


sub do_manpage
{
    $/ = "";  # read one paragraph at a time
    while (<OLD>) {
        # # Downgrade all <Hn> tags by one
        # s{(</?h)(\d)\b([^>]*>)}{$1.($2 +1 ).$3}gieo;

        # Get rid of any mailto: links
        s{<link[^>]+mailto:[^>]+>}{}i;

        # Remove all <hr>
        s{<hr\b[^>]*>}{}iog;

        # # Change <a name> to <a id>
        # s{<a name="}{<a id="}iog;

        # Make links to other man pages
        s{(<b>$man_re\(\d\)</b>)}{<a href="$2.html">$1</a>}og;

        print NEW;
    }
}
# do_manpage
