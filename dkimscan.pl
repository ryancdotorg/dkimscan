#!/usr/bin/perl -w
# Copyright (c) 2018 Ryan Castellucci
# License: AGPLv3
use strict;

use Crypt::OpenSSL::RSA;
use Crypt::OpenSSL::Bignum;

use MIME::Base64;

use Digest::SHA qw(sha1_hex);

use Net::DNS;
use Net::DNS::Async;

use List::Util qw(min max);

use Data::Dumper;

my $QUIET = $ENV{QUIET} || 0;

# Possible substitutions
# %N01,10% : range of numbers with leading zeros
# %N1,10%  : range of numbers without leading zeros
# %D%      : domain name
# %D1%     : first part of domain name from the left
# %D1,3%   : first through third parts of domain name
# %D-1%    : last part of domain name
# %D-3,-1% : last three parts of domain name
# %La,b,c% : list of strings
# %Ofoo%   : optional string

### INITIALIZATION ###

my %found = ();

# Function table
my $ft = { N   => \&gen_numeric_range,
           D   => \&gen_domain_parts,
           L   => \&gen_list,
           O   => \&gen_optional,
};

my $res  = Net::DNS::Resolver->new(nameservers => [qw(1.1.1.1 1.0.0.1)]);
my $adns = Net::DNS::Async->new(QueueSize => 2048, Retries => 3);
# Net::DNS::Async has no API for setting/changing this, so modify the object
$adns->{Resolver} = $res;

### MAIN ###

scan_selectors(domain => $ARGV[0], scan_f => \&async_scanner, rules => $ARGV[1]);

$adns->await();

### ASYNCRONOUS SCANNER FUNCTIONS ###

sub async_scanner {
    my $selector = shift || 'dummy';
    my $g_data   = shift || {}; # expect hashref
    my $domain   = $g_data->{'domain'} || die;
  
    #print "checking $selector._domainkey.$domain\n";

    $adns->add(\&response_handler, "$selector._domainkey.$domain", "TXT");
}

sub response_handler {
  my $response = shift;

  return unless(defined($response));
  return if ($response->header->rcode eq 'NXDOMAIN');

  my ($domain, $selector, $mode);
  my ($question) = $response->question;
  unless ($question) {
    warn "\$question undefined\n";
    return;
  }
  my $qname = $question->qname;

  if ($qname =~ /(.+)\._domainkey\.(.+)/) {
    ($selector, $domain) = ($1, $2);
  } else {
    return;
  }

  if ($found{$selector}) {
    return;
  }
  $found{$selector} = 1;

  foreach my $rr ($response->answer) {
    next unless($rr->type eq 'TXT');
    my $h = parse_dkim_txt(join('', $rr->txtdata));
    next unless($h && $h->{'p'});
    print  "# fqdn: $qname\n" unless ($QUIET);
    print  "# txt:  " . $rr->rdatastr . "\n" unless ($QUIET);
    print  "# key:  " . $h->{'p'} . "\n" unless ($QUIET);
    if (defined($h->{'t'}) && lc($h->{'t'}) eq 'y') {
      $mode = 'TEST';
    } else {
      $mode = 'PROD';
    }
    my $x509 = raw_to_x509($h->{'p'});
    my ($rsa_pub, $pub_fp) = (Crypt::OpenSSL::RSA->new_public_key($x509), sha1_hex(decode_base64($h->{'p'})));
    printf("# size: %4d bits\n", $rsa_pub->size * 8) unless ($QUIET);
    my ($n, $e) = $rsa_pub->get_key_parameters;

    print  "# n:    " . $n->to_decimal . "\n" unless ($QUIET);
    print  "# e:    " . $e->to_decimal . "\n" unless ($QUIET);
    printf("# fp:   %s %4d %s %s %s\n\n", $pub_fp, $rsa_pub->size * 8, $domain, $selector, $mode);
    print $rsa_pub->get_public_key_x509_string() . "\n" unless ($QUIET);
  }
}

### DNS SCANNING FUNCTIONS ###

sub raw_to_x509
{
  my $raw = shift;
  return join("\n", '-----BEGIN PUBLIC KEY-----',
                    unpack('(a64)*', $raw),
                    "-----END PUBLIC KEY-----\n");
}

sub parse_dkim_txt {
  my $txt = shift;
  $txt =~ s/\"\s+\"/ /g;

  my $dkim = {};
  while ($txt =~ s/\A\s*([^=]+)=([^;]*?)(\\?;\s*|\s*\z)//) {
    $dkim->{$1} = $2;
  }

  if ($dkim->{p}) {
    $dkim->{p} =~ s/\s+//g;
    $dkim->{p} = base64pad($dkim->{p});
  }

  return $dkim;
}

sub base64pad {
  my $b64 = shift;
  while (length($b64) % 4) { $b64 .= '='; }
  return $b64;
}

### SELECTOR GENERATION FUNCTIONS ###

sub scan_selectors {
    my %args = @_;
    my $g_data->{'domain'} = $args{'domain'};
    my $scan_f = $args{'scan_f'} || sub { printf("%s\n", shift); };
    my $rules  = $args{'rules'} || undef;

    if (defined($rules)) {
        open(DATA, '<', $rules) || die "Could not open '$rules': $!";
    }

    while (my $line = <DATA>) {
        chomp $line;

        # strip spaces
        $line =~ s/\s+//g;

        # skip blank lines and comments
        next if ($line =~ /\A\z/);
        next if ($line =~ /\A[#;]/);

        last if ($line eq 'EoF');

        #print "LINE: $line\n";

        # Break up the wordlist entry into elements
        # and put them into a reversed list
        my @elements;
        while ((my $idx = index($line, '%')) >= 0) {
            if ($idx) {
              unshift(@elements, substr($line, 0, $idx));
              $line = substr($line, $idx);
            }
            last unless(($idx = index($line, '%', 1)) > 0);
            unshift(@elements, substr($line, 0, $idx+1));
            $line = substr($line, $idx+1);
	}
        unshift(@elements, $line) if ($line);

        #print Dumper \@elements;
        my $gen_f = sub { $scan_f->(shift, $g_data) };

        # builds up a series of nested loops via closures
        foreach my $element (@elements) {
            next if ($element eq '');
            # Copy $gen_f into a new coderef for use in the colsure
            my $next_f = $gen_f;
            if ($element =~ /\A\%([A-Z])(.*)\%\z/) {
                my $id = $1;
                my $g_args = [split(/,/, $2 || '')];
                $gen_f = sub {
                    $ft->{$id}->(shift, $g_args, $g_data, $next_f);
                };
            } else {
                $gen_f = sub {
                    gen_string(shift, $element, $g_data, $next_f);
                };
            }
        }
        # run the scan
	$gen_f->('');
    }
}

# Stuff in g_data
# domain: the domain name we're checking

sub gen_numeric_range {
    my $prefix = shift || '';
    my $g_args = shift || []; # expect arrayref
    my $g_data = shift || {}; # expect hashref
    my $next_f = shift || sub { undef; };

    if (scalar(@$g_args != 2)) {
        die "bad args to %N expansion";
    }

    if ($g_args->[0] =~ /\A0/) {
      my $len = length($g_args->[0]);
      foreach my $n ($g_args->[0] .. $g_args->[1]) {
        $next_f->(sprintf("%s%0${len}d", $prefix, $n));
      }
    } else {
      foreach my $n ($g_args->[0] .. $g_args->[1]) {
        $next_f->($prefix . $n);
      }
    }
}

sub gen_domain_parts {
    my $prefix = shift || '';
    my $g_args = shift || []; # expect arrayref
    my $g_data = shift || {}; # expect hashref
    my $next_f = shift || sub { undef; };

    my @d = split(/\./, $g_data->{'domain'});
    my $parts = scalar(@d);

    if (scalar(@$g_args) == 0) {
        $next_f->($g_data->{'domain'});
    } elsif (scalar(@$g_args) == 1) {
        # make the domain part index start at 1
        $g_args->[0]-- if ($g_args->[0] > 0);

        # make sure the value is in range
        $g_args->[0] = min($g_args->[0], $#d);
        $g_args->[0] = max($g_args->[0], -$parts);

        $next_f->($d[$g_args->[0]]);
    } elsif (scalar(@$g_args) == 2){
        # make the domain part index start at 1
        $g_args->[0]-- if ($g_args->[0] > 0);
        $g_args->[1]-- if ($g_args->[1] > 0);

        # make sure the values are in range
        $g_args->[0] = min($g_args->[0], $#d);
        $g_args->[0] = max($g_args->[0], -$parts);
        $g_args->[1] = min($g_args->[1], $#d);
        $g_args->[1] = max($g_args->[1], -$parts);

        # Take an array slice and join it with periods
        $next_f->( join('.', (@d)[$g_args->[0]..$g_args->[1]] ) );
    } else {
        die "bad args to %D expansion";
    }
}

sub gen_list {
    my $prefix = shift || '';
    my $g_args = shift || []; # expect arrayref
    my $g_data = shift || {}; # expect hashref
    my $next_f = shift || sub { undef; };

    foreach my $item (@$g_args) {
        $next_f->($prefix . $item);
    }
}

sub gen_optional {
    my $prefix = shift || '';
    my $g_args = shift || []; # expect arrayref
    my $g_data = shift || {}; # expect hashref
    my $next_f = shift || sub { undef; };

    if (scalar(@$g_args != 1)) {
        die "bad args to %O expansion";
    }
    $next_f->($prefix);
    $next_f->($prefix . $g_args->[0]);
}

sub gen_string {
    my $prefix = shift || '';
    my $string = shift || '';
    my $g_data = shift || {}; # expect hashref
    my $next_f = shift || sub { undef; };

    $next_f->($prefix . $string);
}

__DATA__
; built-in selector scan rules

; common strings from the wild
k%N1,20%
default
google
mail
class
s%L384,512,768,1024,2048%
m%L384,512,768,1024,2048%
smtpapi
dkim
bfi
spop
spop1024
beta
domk
key%N1,20%
dk
ei
yesmail%N1,20%
smtpout
sm
selector%N1,20%
authsmtp
alpha
v%N1,5%
mesmtp
cm
prod
pm
gamma
dkrnt
dkimrnt
private
gmmailerd
pmta
m%N1,20%
x
selector
qcdkim
postfix
mikd
main
m
dk20050327
delta
yibm
wesmail
test
stigmate
squaremail
sitemail
sel%N1,20%
sasl
sailthru
rsa%N1,20%
responsys
publickey
proddkim
my%N1,20%
mail-in
ls%N1,20%
key
ED-DKIM
ebmailerd
eb%N1,20%
dk%N1,20%
Corporate
care
0xdeadbeef
yousendit
www
tilprivate
testdk
snowcrash
smtpcomcustomers
smtpauth
smtp
sl%N1,20%
sl
sharedpool
ses
server
scooby
scarlet
safe
s
s%N1,20%
pvt
primus
primary
postfix.private
outbound
originating
one
neomailout
mx
msa
monkey
mkt
mimi
mdaemon
mailrelay
mailjet
mail-dkim
mailo
mandrill
lists
iweb
iport
id
hubris
googleapps
global
gears
exim4u
exim
et
dyn
duh
dksel
dkimmail
corp
centralsmtp
ca
bfi
auth
allselector
zendesk1
; search rules

; uncreative
dk%N01,20%
dk%N1,9%
dkim%N01,20%
dkim%N1,9%
dkim
proddkim
testdkim
%Ldkim,dk,testdkim,proddkim%%L256,384,512,768,1024,2048%

; year
%L,mail,mail-,dkim,dkim-,sel,sel-,d,dk,s,pf%%N2005,2018%

; year and month
%L,mail,mail-,dkim,dkim-,sel,sel-,d,dk,s%%N2005,2018%%O-%%N01,12%

; two digit year and month
%L,scph%%N05,18%%O-%%N01,12%

; abrv month and year
$Ljan,feb,mar,apr,may,jun,jul,aug,sep,oct,nov,dec%%N2005,2018%

; year and quarter
q%N1,4%%O-%%N2005,2018%
%N2005,2018%%O-%q%N1,4%

; domain-based
%D%      %L,-dkim,-google%
%D1%     %L,-dkim,-google%
%D2%     %L,-dkim,-google%
%D1,2%   %L,-dkim,-google%
%D-2,-1% %L,-dkim,-google%
%D-3,-1% %L,-dkim,-google%

; domain and number
%D%      %O-% %N1,20%
%D1%     %O-% %N1,20%
%D2%     %O-% %N1,20%
%D1,2%   %O-% %N1,20%
%D-2,-1% %O-% %N1,20%
%D-3,-1% %O-% %N1,20%

; domain and year
%D%      %O-% %N2005,2018%
%D1%     %O-% %N2005,2018%
%D2%     %O-% %N2005,2018%
%D1,2%   %O-% %N2005,2018% 
%D-2,-1% %O-% %N2005,2018%
%D-3,-1% %O-% %N2005,2018%

; observed patterns
ED%N2005,2018%%O-%%N01,12%

; year, month, day - includes some bogus days
; THESE TAKE A WHILE
%L,mail,mail-,dkim,dkim-,s,dk,d%%N2005,2018%%N01,12%%N01,31%%L,01%
%L,mail,mail-,dkim,dkim-,s,dk,d%%N2005,2018%-%N01,12%-%N01,31%

; brute force search of short selectors
; REALLY SLOW, some disabled by default
; numeric range expansion operator works on letters because perl is awesome
%Na,z%
%Na,z%%Na,z%
#%Na,z%%Na,z%%Na,z%
%Na,z%%N0,9%
%Na,z%%Na,z%%N0,9%
#%Na,z%%Na,z%%Na,z%%N0,9%
%Na,z%%N0,9%%N0,9%
#%Na,z%%Na,z%%N0,9%%N0,9%
#%Na,z%%Na,z%%Na,z%%N0,9%%N0,9%
