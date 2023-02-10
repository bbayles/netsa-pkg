#!/usr/bin/perl

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

# name of this script
my $NAME = $0;
$NAME =~ s,.*/,,;

# name of project; used in the download links
my $project = 'libfixbuf';

# Value to use in @licenses to skip a release in the output
my $no_print = 'NO_PRINT';

# This array allows suppressing a release from the output and also
# determines whether to include a download link and the license to
# use in the click-through pop-up.
#
# Each entry is a pair (an array) containing a regex and a string.
# The regex is compared to the version in the NEWS file (the text
# after "Version " and before the date), and if it matches, the string
# is checked.  If the string has the value $no_print, the entry is not
# printed; if the string is empty or undef, the entry is printed
# without a download link; otherwise the string names the license to
# use for the download link.  If the regex does not match, the next
# entry in the array is tried.  If no match for the version is found
# in the table, the entry is printed but no download link is added for
# that release.
#
my @licenses = (
    # no download links for fixbuf 0.x.
    [qr/^1\.\d/, 'lgpl'],     # fixbuf 1.x
    [qr/^2\.\d/, 'lgpl3'],    # fixbuf 2.x
    # do not include 3.x releases here
    [qr/^3\.\d/, $no_print],  # fixbuf 3.x
    # original values for other releases
    #|[qr/^3\.\d/, 'gpl'],      # fixbuf 3.x
);

print <<HEAD;
<?xml version="1.0"?>
<p:project xmlns:p="http://netsa.cert.org/xml/project/1.0"
           xmlns="http://www.w3.org/1999/xhtml"
           xmlns:xi="http://www.w3.org/2001/XInclude">
HEAD

# slurp in all of the standard input
my $content;
{
    local $/ = undef;
    $content = <STDIN>;
}


# This regexp is pretty liberal, so as to be able to grok most NEWS formats.
while ($content =~ /^Version (\d[^:]*?):?\s+\(?([^\n]+?)\)?\s*\n\s*=+\s*((?:.(?!^Version))+)/msg)
{
    my ($vers, $date, $notes) = ($1, $2, $3);

    # determine whether to print and if so, whether have a download
    # link and the license to use
    my $download = "";
    for my $re_lic (@licenses) {
        my ($re, $license) = @$re_lic;
        if ($vers =~ $re) {
            if (!$license) {
                # print entry with no download link
            }
            elsif ($license eq $no_print) {
                $download = $no_print;
            }
            else {
                $download = <<RELFILE;
  <p:file href="/releases/$project-$vers.tar.gz" license="$license"/>
RELFILE
            }
            last;
        }
    }
    if ($download eq $no_print) {
        next;
    }

    print <<RELHEAD1;
 <p:release>
  <p:version>$vers</p:version>
  <p:date>$date</p:date>
$download  <p:changelog>
   <ul>
RELHEAD1

    # html escape the notes
    $notes =~ s/&/&amp;/g;
    $notes =~ s/</&lt;/g;
    $notes =~ s/>/&gt;/g;

    # split notes into individual items: assumes items are double spaced
    $notes =~ s/\n+$//s;
    my @items = split /\n\n+/, $notes;

    for my $item (@items) {
        print "    <li>\n$item\n    </li>\n";
    }

    print <<RELTAIL;
   </ul>
  </p:changelog>
 </p:release>
RELTAIL
}
print <<TAIL;
</p:project>
TAIL
