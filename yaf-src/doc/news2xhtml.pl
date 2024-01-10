#! /usr/bin/env perl

##  Copyright 2010-2023 Carnegie Mellon University
##  See license information in LICENSE.txt.
##
##  @DISTRIBUTION_STATEMENT_BEGIN@
##  YAF 2.15.0
##
##  Copyright 2023 Carnegie Mellon University.
##
##  NO WARRANTY. THIS CARNEGIE MELLON UNIVERSITY AND SOFTWARE ENGINEERING
##  INSTITUTE MATERIAL IS FURNISHED ON AN "AS-IS" BASIS. CARNEGIE MELLON
##  UNIVERSITY MAKES NO WARRANTIES OF ANY KIND, EITHER EXPRESSED OR IMPLIED,
##  AS TO ANY MATTER INCLUDING, BUT NOT LIMITED TO, WARRANTY OF FITNESS FOR
##  PURPOSE OR MERCHANTABILITY, EXCLUSIVITY, OR RESULTS OBTAINED FROM USE OF
##  THE MATERIAL. CARNEGIE MELLON UNIVERSITY DOES NOT MAKE ANY WARRANTY OF
##  ANY KIND WITH RESPECT TO FREEDOM FROM PATENT, TRADEMARK, OR COPYRIGHT
##  INFRINGEMENT.
##
##  Licensed under a GNU GPL 2.0-style license, please see LICENSE.txt or
##  contact permission@sei.cmu.edu for full terms.
##
##  [DISTRIBUTION STATEMENT A] This material has been approved for public
##  release and unlimited distribution.  Please see Copyright notice for
##  non-US Government use and distribution.
##
##  GOVERNMENT PURPOSE RIGHTS - Software and Software Documentation
##  Contract No.: FA8702-15-D-0002
##  Contractor Name: Carnegie Mellon University
##  Contractor Address: 4500 Fifth Avenue, Pittsburgh, PA 15213
##
##  The Government's rights to use, modify, reproduce, release, perform,
##  display, or disclose this software are restricted by paragraph (b)(2) of
##  the Rights in Noncommercial Computer Software and Noncommercial Computer
##  Software Documentation clause contained in the above identified
##  contract. No restrictions apply after the expiration date shown
##  above. Any reproduction of the software or portions thereof marked with
##  this legend must also reproduce the markings.
##
##  This Software includes and/or makes use of Third-Party Software each
##  subject to its own license.
##
##  DM23-2313
##  @DISTRIBUTION_STATEMENT_END@

use warnings;
use strict;

# name of this script
my $NAME = $0;
$NAME =~ s,.*/,,;

# name of project; used in the download links
my $project = 'yaf';

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
    # Files for all 1.x and later releases are available. A file for
    # 0.8.0 is available, which was the final 0.x release

    # Include download links for 0.8.0, 1.x, 2.x
    [qr/^0\.8\.0$/,  'gpl'],  # yaf 0.8.0
    [qr/^1\.\d/,     'gpl'],  # yaf 1.x
    [qr/^2\.\d/,     'gpl'],  # yaf 2.x

    # Do not print 3.x
    [qr/^3\.\d/, $no_print],  # yaf 3.x

    # Other 0.x releases match nothing: they are printed but do not
    # have a download link

    # original values for other releases
    #[qr/^0\.8\.0$/,  'gpl'],  # yaf 0.8.0
    #[qr/^1\.\d/,     'gpl'],  # yaf 1.x
    #[qr/^2\.\d/,     'gpl'],  # yaf 2.x
    #[qr/^3\.\d/,     'gpl'],  # yaf 3.x
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

    if ($notes =~ /SPONSOR ONLY RELEASE/) {
        next;
    }

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

    # indentation under the <ul>
    my $indent = " " x 4;

    # First, see if items are delimited by \n\n
    if ($notes =~ m@(.+?)\n\n+?@) {
        while ($notes =~ m@(.+?)\n\n+?@msg) {
            print $indent, "<li>$1</li>\n";
        }
        # The last item will be skipped if there aren't two blank lines
        # at the end, so we look for that and fix it here.
        if ($notes =~ /(.+?)(?:\n(?!\n))$/) {
            print $indent, "<li>$1</li>\n";
        }
    }
    # Otherwise, assume items are delimited by \n
    else {
        while ($notes =~ m@(.*?)\n+@msg) {
            print $indent, "<li>$1</li>\n";
        }
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


__END__
