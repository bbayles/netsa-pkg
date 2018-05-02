#!/usr/bin/perl

## libfixbuf 2.0
##
## Copyright 2018 Carnegie Mellon University. All Rights Reserved.
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
## License.txt or contact permission@sei.cmu.edu for full terms.
##
## [DISTRIBUTION STATEMENT A] This material has been approved for
## public release and unlimited distribution.  Please see Copyright
## notice for non-US Government use and distribution.
##
## Carnegie Mellon® and CERT® are registered in the U.S. Patent and
## Trademark Office by Carnegie Mellon University.

$project = $ARGV[0] or die;
$license = $ARGV[1] or die;
if ($ARGV[2])
{
    # If provided, we'll only spit out <p:file> elements for this number
    # of releases.  We'll still show history for the others, but won't
    # provide download links for them.
    $relkeep = $ARGV[2];
}

print <<HEAD;
<?xml version="1.0"?>
<p:project xmlns:p="http://netsa.cert.org/xml/project/1.0"
           xmlns="http://www.w3.org/1999/xhtml"
           xmlns:xi="http://www.w3.org/2001/XInclude">
HEAD

$ul = 0;
$li = 0;

local $/="undef";
$content = <STDIN>;

$relcount = 0;

# This regexp is pretty liberal, so as to be able to grok most NEWS formats.
while($content =~ /^Version (\d[^:]*?):?\s+\(?([^\n]+?)\)?\s*$\s*=+\s*((?:.(?!Version))+)/msg)
{
    $ver = $1; $date = $2; $notes = $3;
    $relcount++;
    print <<RELHEAD1;
    <p:release>
        <p:version>$ver</p:version>
        <p:date>$date</p:date>
RELHEAD1
;
    if ($relkeep == undef || $relcount <= $relkeep)
    {
    print <<RELHEAD2;
        <p:file href="../releases/$project-$1.tar.gz" license="$license"/>
RELHEAD2

;
    }

    print <<RELHEAD3;
        <p:notes>
            <ul>
RELHEAD3
;
    # First, see if items are delimited by \n\n
    if ($notes =~m@(.+?)\n\n+?@)
    {
        while ($notes =~m@(.+?)\n\n+?@msg)
        {
            print "\t\t<li>$1</li>\n";
        }
        # The last item will be skipped if there aren't two blank lines
        # at the end, so we look for that and fix it here.
        if ($notes =~ /(.+?)(?:\n(?!\n))$/)
        {
            print "\t\t<li>$1</li>\n";
        }
    }
    # Otherwise, assume items are delimited by \n
    else
    {
        while ($notes =~m@(.*?)\n+@msg)
        {
            print "\t\t<li>$1</li>\n";
        }
    }

    print <<RELTAIL;
             </ul>
        </p:notes>
    </p:release>
RELTAIL
;

}
print <<TAIL;
</p:project>
TAIL
