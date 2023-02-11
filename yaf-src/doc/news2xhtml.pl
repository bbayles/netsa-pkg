#! /usr/bin/env perl

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
