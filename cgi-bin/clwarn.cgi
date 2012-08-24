#!/usr/bin/perl
use strict;

use CGI;

my $VERSION = '6.8';

my $cgi = new CGI;

my $url = CGI::escapeHTML($cgi->param('url')) || '';
my $virus = CGI::escapeHTML($cgi->param('virus')) || CGI::escapeHTML($cgi->param('malware')) || '';
my $source = CGI::escapeHTML($cgi->param('source')) || '';
$source =~ s/\/-//;
my $user = CGI::escapeHTML($cgi->param('user')) || '';


my $TITLE_VIRUS = "SquidClamAv $VERSION: Virus detected!";
my $subtitle = 'Virus name';
my $errorreturn = 'This file cannot be downloaded.';
my $urlerror = 'contain a virus.';
if ($virus =~ /Safebrowsing/) {
	$TITLE_VIRUS = "SquidClamAv $VERSION: Unsafe Browsing detected";
	$subtitle = 'Malware / Pishing type';
	$urlerror = 'is listed as suspicious';
	$errorreturn = 'This page can not be diplayed.';
}

# Remove clamd infos
$virus =~ s/stream: //;
$virus =~ s/ FOUND//;


print $cgi->header();

print $cgi->start_html(-title => $TITLE_VIRUS);
print qq{
	<h2 style="color: #FF0000">$TITLE_VIRUS</h2>
	<hr>
	<p>
};
print qq{
	The requested URL $url $urlerror<br>
	$subtitle: $virus
};

print qq{
	<p>
	$errorreturn
	<p>
	Origin: $source / $user
	<p>
	<hr>
	Powered by <a href="http://squidclamav.darold.net/">SquidClamAv $VERSION</a>.
};

print $cgi->end_html();

exit 0;