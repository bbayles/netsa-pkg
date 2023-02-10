#! /usr/bin/perl
#
#  This script modifies the HTML man pages generated by pod2html.  It
#  creates links to other man pages.

## @OPENSOURCE_LICENSE_START@
## libfixbuf 2.0
##
## Copyright 2018-2023 Carnegie Mellon University. All Rights Reserved.
##
## NO WARRANTY. THIS CARNEGIE MELLON UNIVERSITY AND SOFTWARE
## ENGINEERING INSTITUTE MATERIAL IS FURNISHED ON AN "AS-IS"
## BASIS. CARNEGIE MELLON UNIVERSITY MAKES NO WARRANTIES OF ANY KIND,
## EITHER EXPRESSED OR IMPLIED, AS TO ANY MATTER INCLUDING, BUT NOT
## LIMITED TO, WARRANTY OF FITNESS FOR PURPOSE OR MERCHANTABILITY,
## EXCLUSIVITY, OR RESULTS OBTAINED FROM USE OF THE
## MATERIAL. CARNEGIE MELLON UNIVERSITY DOES NOT MAKE ANY WARRANTY OF
## ANY KIND WITH RESPECT TO FREEDOM FROM PATENT, TRADEMARK, OR
## COPYRIGHT INFRINGEMENT.
##
## Released under a GNU-Lesser GPL 3.0-style license, please see
## LICENSE.txt or contact permission@sei.cmu.edu for full terms.
##
## [DISTRIBUTION STATEMENT A] This material has been approved for
## public release and unlimited distribution.  Please see Copyright
## notice for non-US Government use and distribution.
##
## Carnegie Mellon(R) and CERT(R) are registered in the U.S. Patent
## and Trademark Office by Carnegie Mellon University.
##
## DM18-0325
## @OPENSOURCE_LICENSE_END@

use warnings;
use strict;
use File::Copy  qw//;
use File::Temp  qw//;

# name of this script
my $NAME = $0;
$NAME =~ s,.*/,,;

our $old = $ARGV[0];
unless ($old) {
    die "Usage: $NAME <filename>\n\tAdd header and footer to named file\n";
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

        # # Make links to other man pages
        # s{(<b>$man_re\(\d\)</b>)}{<a href="$2.html">$1</a>}og;

        print NEW;
    }
}
# do_manpage
