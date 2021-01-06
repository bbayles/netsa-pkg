#!/usr/bin/perl
#
#  This script modifies the HTML man pages generated by pod2html.  It
#  adds a header and footer, and creates links to other man pages.
#

#
$^W = 1;
use strict;

#
use FindBin qw($Bin);
use lib "$Bin";
# TODO: hard-coding this for now, should generate from build the way SiLK does
our $man_re = "(yaf|yafscii)";

our $old = $ARGV[0];
unless ($old) {
    die "Usage: $0 <filename>\n\tAdd header and footer to named file\n";
}
our $new = "$old.fixed";


our $IDENT = 'RCSIDENT("$Id: $")';



open(OLD, $old)
    or die "Cannot open '$old' for reading: $!\n";
open(NEW, ">$new")
    or die "Cannot open '$new' for writing: $!\n";


do_manpage();


close OLD;
close NEW
    or die "Cannot close '$new': $!\n";

rename $new, $old
    or die "Cannot mv $new $old: $!\n";

exit;


sub add_header
{
    my ($title) = @_;

    if ($title)
    {
        $title = "Documentation - $title";
    }
    else
    {
        $title = "Documentation";
    }

    return <<EOF;
<head>
<title>YAF - $title</title>
<meta http-equiv="Content-Type" content="text/html; charset=iso-8859-1" />

        <link rel="stylesheet" type="text/css" href="../site/style.css" />

</head>
<body>
    <div id="p-body">
      <div id="l-header">
        <img src="../site/sei-logo.png" id="l-sei-logo"
            alt="Software Engineering Institute | Carnegie Mellon&copy;" />
        <div id="l-netsa-logo"><a id="l-netsa-name" href="../index.html"><b>CERT NetSA Security Suite</b></a></div>
        <div id="l-netsa-motto">Monitoring for Large-Scale Networks</div>
        <h1 class="l-page-title">YAF</h1>
        <span id="l-subtitle">Documentation</span>
      </div><!-- l-header -->
      <div id="l-content">
        <div id="l-sidebar">
          <div class="p-sidebar-section">
            <h1><a href="index.html">YAF</a></h1>
            <ul>
              <li><a href="docs.html">Documentation</a></li>
              <li><a href="download.html">Downloads</a></li>
            </ul>
          </div><!-- p-sidebar-section -->
        </div><!-- l-sidebar -->
EOF
}


sub add_footer
{
    return <<EOF;
      </div><!-- l-content -->
      <div id="l-footer">
        &copy; 2006-2020 Carnegie Mellon University
        <span id="l-contact">
          <a href="https://www.sei.cmu.edu/legal/index.cfm">Legal</a> |
          <a href="https://www.sei.cmu.edu/legal/privacy-notice/index.cfm">Privacy Notice</a> |
          <img alt="email address" src="/site/contact_email.png" />
        </span>
      </div>
    </div><!-- p-body -->
</body>
EOF
}


sub do_manpage
{
    # We'll overwrite this with name of man page
    my $title = '';

    # ignore everything until we get to the end of the index, but do
    # cash the title
    my $saw_index = 0;

    # whether we saw the <head>
    my $saw_head = 0;

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
        s{(<strong>$man_re\(\d\)</strong>)}{<a href="$2.html">$1</a>}og;

        # Stash the title
        if (m{(<title>)B\&lt;([^\&]+)&gt;}io) {
            $title = $2;
        }

        # Don't print anything until we see the Perl-generated index
        if ( !$saw_index) {

            #old perldoc
            if (m{(<!-- INDEX END -->)}) {
                $saw_index = 1;
                print NEW add_header($title);
                next;
            }
            next unless m{(<h1 id="NAME">NAME</h1>)};

            $saw_index = 1;
            print NEW add_header($title);
            print NEW "<h1><a name=\"name\">NAME</a></h1>";
            next;
        }
        s{</body\b[^>]*>}{add_footer()}eio;

        print NEW;
    }
}
# do_manpage

