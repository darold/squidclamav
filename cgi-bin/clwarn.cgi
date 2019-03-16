#!/usr/bin/perl
use strict;

use CGI;

my $VERSION = '6.16';

my $cgi = new CGI;

my $url = CGI::escapeHTML(scalar $cgi->param('url')) || '';
my $virus = CGI::escapeHTML(scalar $cgi->param('virus')) || CGI::escapeHTML(scalar $cgi->param('malware')) || '';
my $source = CGI::escapeHTML(scalar $cgi->param('source')) || '';
$source =~ s/\/-//;
my $user = CGI::escapeHTML(scalar $cgi->param('user')) || '';

# libarchive support:
my $recover = CGI::escapeHTML($cgi->param('recover')) || '';
$recover =~ s/^\(null\)$//;
my $default_recoverurl = 'https://' . $cgi->server_name() . "/recover/?id=" if ($recover);


my $TITLE_VIRUS = "SquidClamAv $VERSION: Threat detected!";
my $subtitle = 'Threat name';
my $errorreturn = 'This file cannot be downloaded.';
my $urlerror = 'contains a threat';
if ($virus =~ /Safebrowsing/) {
	$TITLE_VIRUS = "SquidClamAv $VERSION: Unsafe Browsing detected";
	$subtitle = 'Malware / pishing type';
	$urlerror = 'is listed as suspicious';
	$errorreturn = 'This page can not be displayed';
}

# Remove clamd infos
$virus =~ s/stream: //;
$virus =~ s/ FOUND//;


print $cgi->header();

print $cgi->start_html(-title => $TITLE_VIRUS, -bgcolor => "#353535");
print qq{
<style type="text/css">
.visu {
	border:1px solid #C0C0C0;
	color:#FFFFFF;
	position: relative;
	min-width: 13em;
	max-width: 52em;
	margin: 4em auto;
	border: 1px solid ThreeDShadow;
	border-radius: 10px;
	padding: 3em;
	-moz-padding-start: 30px;
	background-color: #8b0000;
}
.visu h2, .visu h3, .visu h4 {
	font-size:130%;
	font-family:"times new roman", times, serif;
	font-style:normal;
	font-weight:bolder;
}
.visu a:link, a:visited, a:active {
	text-decoration: none;
	color:#FFFFFF;
}
.visu a:hover {
	text-decoration: none;
	color:#00FF00;
}
</style>	
	<div class="visu">
	<h2>$TITLE_VIRUS</h2>
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
};

print qq{
	<p>
	Recover: <a target="_blank" href="$default_recoverurl$recover">link to recover data</a>
} if ($recover);

print qq{
	<p>
	<hr>
	<font color="#03ACFF"> Powered by <a href="http://squidclamav.darold.net/">SquidClamAv $VERSION</a>.</font>
	</div>
};

print $cgi->end_html();

exit 0;
