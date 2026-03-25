package Mail::Message::Abuse;

use strict;
use warnings;

our $VERSION = '2.00';

=head1 NAME

Mail::Message::Abuse - Analyse spam email to identify originating hosts, hosted URLs, and suspicious domains.

=head1 SYNOPSIS

    use Mail::Message::Abuse;

    my $analyser = Mail::Message::Abuse->new( verbose => 1 );
    $analyser->parse_email($raw_email_text);

    # Originating IP and its network owner
    my $origin = $analyser->originating_ip();

    # All HTTP/HTTPS URLs found in the body
    my @urls  = $analyser->embedded_urls();

    # All domains extracted from mailto: links and bare addresses in the body
    my @mdoms = $analyser->mailto_domains();

    # All domains mentioned anywhere (union of the above)
    my @adoms = $analyser->all_domains();

    # Full printable report
    print $analyser->report();

=head1 DESCRIPTION

C<Mail::Message::Abuse> examines the raw source of a spam/phishing e-mail
and answers the questions manual abuse investigators ask:

=over 4

=item 1. Where did the message really come from?

Walks the C<Received:> chain, skips private/trusted IPs, and identifies the
first external hop.  Enriches with rDNS, WHOIS/RDAP org name and abuse
contact.

=item 2. Who hosts the advertised web sites?

Extracts every C<http://> and C<https://> URL from both plain-text and HTML
parts, resolves each hostname to an IP, and looks up the network owner.

=item 3. Who owns the reply-to / contact domains?

Extracts domains from C<mailto:> links, bare e-mail addresses in the body,
the C<From:>/C<Reply-To:> headers, and the C<Return-Path:>.  For each
unique domain it gathers:

=over 8

=item * Domain registrar and registrant (WHOIS)

=item * Web-hosting IP and network owner (A record -> RDAP)

=item * Mail-hosting IP and network owner (MX record -> RDAP)

=item * DNS nameserver operator (NS record -> RDAP)

=item * Whether the domain was recently registered (potential flag)

=back

=back

=head1 REQUIRED MODULES

    Net::DNS
    LWP::UserAgent
    HTML::LinkExtor
    Socket
    IO::Socket::INET
    MIME::QuotedPrint  (core since Perl 5.8)
    MIME::Base64       (core since Perl 5.8)

All are available from CPAN.

=cut

# -----------------------------------------------------------------------
# Core dependencies (always available)
# -----------------------------------------------------------------------
use Socket          qw( inet_aton inet_ntoa );
use IO::Socket::INET;
use MIME::QuotedPrint qw( decode_qp );
use MIME::Base64      qw( decode_base64 );

# Optional - gracefully degraded
my $HAS_NET_DNS;
BEGIN { $HAS_NET_DNS = eval { require Net::DNS; 1 } }

my $HAS_LWP;
BEGIN { $HAS_LWP = eval { require LWP::UserAgent; 1 } }

my $HAS_HTML_LINKEXTOR;
BEGIN { $HAS_HTML_LINKEXTOR = eval { require HTML::LinkExtor; 1 } }

# -----------------------------------------------------------------------
# Constants
# -----------------------------------------------------------------------

my @PRIVATE_RANGES = (
	qr/^0\.0\.0\.0$/,
	qr/^127\./,
	qr/^10\./,
	qr/^192\.168\./,
	qr/^172\.(?:1[6-9]|2\d|3[01])\./,
	qr/^169\.254\./,
	qr/^::1$/,
	qr/^fc/i,
	qr/^fd/i,
);

my @RECEIVED_IP_RE = (
    qr/\[\s*([\d.]+)\s*\]/,
    qr/\(\s*[\w.-]*\s*\[?\s*([\d.]+)\s*\]?\s*\)/,
    qr/from\s+[\w.-]+\s+([\d.]+)/,
    qr/([\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3})/,
);

# Domains we never bother reporting on - they are the infrastructure,
# not the criminal.
my %TRUSTED_DOMAINS = map { $_ => 1 } qw(
    gmail.com googlemail.com yahoo.com outlook.com hotmail.com
    google.com microsoft.com apple.com amazon.com
);

# Known URL shortener / redirect domains — real destination is hidden
my %URL_SHORTENERS = map { $_ => 1 } qw(
    bit.ly      bitly.com   tinyurl.com  t.co        ow.ly
    goo.gl      is.gd       buff.ly      ift.tt       dlvr.it
    short.link  rebrand.ly  tiny.cc      cutt.ly      rb.gy
    shorturl.at bl.ink      smarturl.it  yourls.org   clicky.me
    snip.ly     adf.ly      bc.vc        lnkd.in      fb.me
    youtu.be
);

# Well-known providers: use their specific abuse address / report URL
# rather than whatever a generic WHOIS lookup might return.
my %PROVIDER_ABUSE = (
    # Google / Gmail
    'google.com'        => { email => 'abuse@google.com',      note => 'Also report Gmail accounts via https://support.google.com/mail/contact/abuse' },
    'gmail.com'         => { email => 'abuse@google.com',      note => 'Report Gmail spam via https://support.google.com/mail/contact/abuse' },
    'googlemail.com'    => { email => 'abuse@google.com',      note => 'Report via https://support.google.com/mail/contact/abuse' },
    '1e100.net'         => { email => 'abuse@google.com',      note => 'Google infrastructure' },
    # Microsoft / Outlook / Hotmail
    'microsoft.com'     => { email => 'abuse@microsoft.com',   note => 'Also report via https://www.microsoft.com/en-us/wdsi/support/report-unsafe-site' },
    'outlook.com'       => { email => 'abuse@microsoft.com',   note => 'Report Outlook spam: https://support.microsoft.com/en-us/office/report-phishing' },
    'hotmail.com'       => { email => 'abuse@microsoft.com',   note => 'Report via https://support.microsoft.com/en-us/office/report-phishing' },
    'live.com'          => { email => 'abuse@microsoft.com',   note => 'Microsoft consumer mail' },
    'office365.com'     => { email => 'abuse@microsoft.com',   note => 'Microsoft 365 infrastructure' },
    'protection.outlook.com' => { email => 'abuse@microsoft.com', note => 'Microsoft EOP gateway' },
    # Yahoo
    'yahoo.com'         => { email => 'abuse@yahoo-inc.com',   note => 'Also use https://io.help.yahoo.com/contact/index' },
    'yahoo.co.uk'       => { email => 'abuse@yahoo-inc.com',   note => 'Yahoo UK' },
    # Apple
    'apple.com'         => { email => 'reportphishing@apple.com', note => 'iCloud / Apple Mail abuse' },
    'icloud.com'        => { email => 'reportphishing@apple.com', note => 'iCloud abuse' },
    'me.com'            => { email => 'reportphishing@apple.com', note => 'Apple legacy mail' },
    # Amazon / AWS
    'amazon.com'        => { email => 'abuse@amazonaws.com',   note => 'Also https://aws.amazon.com/forms/report-abuse' },
    'amazonaws.com'     => { email => 'abuse@amazonaws.com',   note => 'AWS abuse form: https://aws.amazon.com/forms/report-abuse' },
    'amazonses.com'     => { email => 'abuse@amazonaws.com',   note => 'Amazon SES sending infrastructure' },
    # Cloudflare
    'cloudflare.com'    => { email => 'abuse@cloudflare.com',  note => 'Report via https://www.cloudflare.com/abuse/' },
    # Fastly / Akamai
    'fastly.net'        => { email => 'abuse@fastly.com',      note => 'Fastly CDN' },
    'akamai.com'        => { email => 'abuse@akamai.com',      note => 'Akamai CDN' },
    'akamaitechnologies.com' => { email => 'abuse@akamai.com', note => 'Akamai CDN' },
    # Namecheap
    'namecheap.com'     => { email => 'abuse@namecheap.com',   note => 'Registrar abuse' },
    # GoDaddy
    'godaddy.com'       => { email => 'abuse@godaddy.com',     note => 'Registrar/host abuse' },
    # SendGrid / Twilio
    'sendgrid.net'      => { email => 'abuse@sendgrid.com',    note => 'ESP — include full headers' },
    'sendgrid.com'      => { email => 'abuse@sendgrid.com',    note => 'ESP — include full headers' },
    # Mailchimp / Mandrill
    'mailchimp.com'     => { email => 'abuse@mailchimp.com',   note => 'ESP abuse' },
    'mandrillapp.com'   => { email => 'abuse@mailchimp.com',   note => 'Mandrill transactional ESP' },
    # OVH
    'ovh.net'           => { email => 'abuse@ovh.net',         note => 'OVH hosting' },
    'ovh.com'           => { email => 'abuse@ovh.com',         note => 'OVH hosting' },
    # Hetzner
    'hetzner.com'       => { email => 'abuse@hetzner.com',     note => 'Hetzner hosting' },
    # Digital Ocean
    'digitalocean.com'  => { email => 'abuse@digitalocean.com',note => 'DO abuse form: https://www.digitalocean.com/company/contact/#abuse' },
    # Linode / Akamai
    'linode.com'        => { email => 'abuse@linode.com',      note => 'Linode/Akamai Cloud' },
    # TPG / Internode (Australia — relevant for this email's sending IP)
    'tpgi.com.au'       => { email => 'abuse@tpg.com.au',      note => 'TPG Telecom Australia' },
    'tpg.com.au'        => { email => 'abuse@tpg.com.au',      note => 'TPG Telecom Australia' },
    'internode.on.net'  => { email => 'abuse@internode.on.net',note => 'Internode Australia' },
);

# -----------------------------------------------------------------------
# Constructor
# -----------------------------------------------------------------------

=head1 METHODS

=head2 new( %options )

    my $a = Mail::Message::Abuse->new(
        timeout        => 15,
        trusted_relays => ['203.0.113.0/24'],
        verbose        => 0,
    );

=cut

sub new {
	my ($class, %opts) = @_;

    return bless {
        timeout        => $opts{timeout}        // 10,
        trusted_relays => $opts{trusted_relays} || [],
        verbose        => $opts{verbose}        || 0,
        _raw           => '',
        _headers       => [],
        _body_plain    => '',
        _body_html     => '',
        _received      => [],
        _origin        => undef,
        _urls          => undef,    # lazy
        _mailto_domains=> undef,    # lazy
        _domain_info   => {},       # cache: domain -> hashref
    }, $class;
}

# -----------------------------------------------------------------------
# Public: parse
# -----------------------------------------------------------------------

=head2 parse_email( $text )

Feed the raw RFC 2822 source to the analyser.  Accepts a scalar or
scalar-ref.  Handles C<multipart>, C<quoted-printable>, and C<base64>
bodies automatically.

=cut

sub parse_email {
    my ($self, $text) = @_;
    $text = $$text if ref $text;
    $self->{_raw}            = $text;
    $self->{_origin}         = undef;
    $self->{_urls}           = undef;
    $self->{_mailto_domains} = undef;
    $self->{_domain_info}    = {};
    $self->{_risk}           = undef;
    $self->{_auth_results}   = undef;

    $self->_split_message($text);
    return $self;
}

# -----------------------------------------------------------------------
# Public: originating host
# -----------------------------------------------------------------------

=head2 originating_ip()

Returns a hashref:

    {
        ip         => '209.85.218.67',
        rdns       => 'mail-ej1-f67.google.com',
        org        => 'Google LLC',
        abuse      => 'network-abuse@google.com',
        confidence => 'high',
        note       => 'First external hop in Received: chain',
    }

=cut

sub originating_ip {
	my $self = $_[0];

	$self->{_origin} //= $self->_find_origin();
	return $self->{_origin};
}

# -----------------------------------------------------------------------
# Public: HTTP/HTTPS URLs
# -----------------------------------------------------------------------

=head2 embedded_urls()

Returns a list of hashrefs for every HTTP/HTTPS URL in the body:

    {
        url   => 'https://spamsite.example/offer',
        host  => 'spamsite.example',
        ip    => '198.51.100.7',
        org   => 'Dodgy Hosting Ltd',
        abuse => 'abuse@dodgy.example',
    }

=cut

sub embedded_urls {
    my ($self) = @_;
    $self->{_urls} //= $self->_extract_and_resolve_urls();
    return @{ $self->{_urls} };
}

# -----------------------------------------------------------------------
# Public: mailto / reply-to / from domains
# -----------------------------------------------------------------------

=head2 mailto_domains()

Returns a list of hashrefs, one per unique non-infrastructure domain found
in C<mailto:> links, bare e-mail addresses in the body, and the envelope /
header fields C<From:>, C<Reply-To:>, C<Return-Path:>.

Each hashref contains:

    {
        domain      => 'sminvestmentsupplychain.com',
        source      => 'mailto in body',

        # Web hosting
        web_ip      => '104.21.30.10',
        web_org     => 'Cloudflare Inc',
        web_abuse   => 'abuse@cloudflare.com',

        # Mail hosting (MX)
        mx_host     => 'mail.example.com',
        mx_ip       => '198.51.100.5',
        mx_org      => 'Hosting Corp',
        mx_abuse    => 'abuse@hostingcorp.example',

        # DNS authority (NS)
        ns_host     => 'ns1.example.com',
        ns_ip       => '198.51.100.1',
        ns_org      => 'DNS Provider Inc',
        ns_abuse    => 'abuse@dnsprovider.example',

        # Domain registration (WHOIS)
        registrar   => 'GoDaddy.com LLC',
        registered  => '2024-11-01',
        expires     => '2025-11-01',
        recently_registered => 1,   # flag: < 180 days old

        # Raw domain WHOIS text (first 2 KB)
        whois_raw   => '...',
    }

=cut

sub mailto_domains {
    my ($self) = @_;
    $self->{_mailto_domains} //= $self->_extract_and_analyse_domains();
    return @{ $self->{_mailto_domains} };
}

=head2 all_domains()

Union of every domain seen across HTTP URLs and mailto/reply domains.

=cut

sub all_domains {
	my $self = $_[0];
	my %seen;
	my @out;
	for my $u ($self->embedded_urls()) {
		my $dom = _registrable($u->{host});
		push @out, $dom if $dom && !$seen{$dom}++;
	}
	for my $d ($self->mailto_domains()) {
		my $dom = _registrable($d->{domain}) // $d->{domain};
		push @out, $dom if $dom && !$seen{$dom}++;
	}
	return @out;
}

# -----------------------------------------------------------------------
# Private: MIME encoded-word decoder  (=?charset?B/Q?...?=)
# -----------------------------------------------------------------------

sub _decode_mime_words {
    my ($self, $str) = @_;
    return '' unless defined $str;
    $str =~ s/=\?([^?]+)\?([BbQq])\?([^?]*)\?=/_decode_ew($1,$2,$3)/ge;
    return $str;
}

sub _decode_ew {
    my ($charset, $enc, $text) = @_;
    my $raw;
    if (uc($enc) eq 'B') {
        $raw = decode_base64($text);
    } else {
        $text =~ s/_/ /g;
        $raw  = decode_qp($text);
    }
    # Best-effort UTF-8; silently ignore decode errors
    if (lc($charset) ne 'utf-8') {
        # For non-UTF-8 charsets just return the raw bytes — good enough
        # for display-name spoof detection which only needs ASCII matching
    }
    return $raw;
}

# -----------------------------------------------------------------------
# Public: risk assessment
# -----------------------------------------------------------------------

=head2 risk_assessment()

Returns a hashref with an overall risk level and a list of specific
red flags found in the message:

    {
        level => 'HIGH',          # HIGH | MEDIUM | LOW | INFO
        score => 7,               # raw weighted score
        flags => [
            { severity => 'HIGH',   flag => 'recently_registered_domain',
              detail => 'firmluminary.com registered 2025-09-01 (< 180 days ago)' },
            { severity => 'MEDIUM', flag => 'residential_sending_ip',
              detail => 'rDNS 120-88-161-249.tpgi.com.au looks like a broadband line' },
            { severity => 'MEDIUM', flag => 'url_shortener',
              detail => 'bit.ly used - real destination hidden' },
            ...
        ],
    }

=cut

sub risk_assessment {
	my $self = $_[0];
	return $self->{_risk} if $self->{_risk};

	my @flags;
	my $score = 0;

    my $flag = sub {
        my ($severity, $name, $detail) = @_;
        my %weight = (HIGH => 3, MEDIUM => 2, LOW => 1, INFO => 0);
        $score += $weight{$severity} // 1;
        push @flags, { severity => $severity, flag => $name, detail => $detail };
    };

    # ---- Originating IP checks ----
    my $orig = $self->originating_ip();
    if ($orig) {
        # Residential / broadband rDNS patterns
        if ($orig->{rdns} && $orig->{rdns} =~ /
            \d+[-_.]\d+[-_.]\d+[-_.]\d+   # dotted-quad in rDNS
            | (?:dsl|adsl|cable|broad|dial|dynamic|dhcp|ppp|
                 residential|cust|home|pool|client|user|
                 static\d|host\d)
        /xi) {
            $flag->('HIGH', 'residential_sending_ip',
                "Sending IP $orig->{ip} rDNS '$orig->{rdns}' looks like a broadband/residential line, not a legitimate mail server");
        }

        # No rDNS at all
        if (!$orig->{rdns} || $orig->{rdns} eq '(no reverse DNS)') {
            $flag->('HIGH', 'no_reverse_dns',
                "Sending IP $orig->{ip} has no reverse DNS — legitimate mail servers always have rDNS");
        }

        # Low confidence origin
        if ($orig->{confidence} eq 'low') {
            $flag->('MEDIUM', 'low_confidence_origin',
                "Originating IP taken from unverified header ($orig->{note})");
        }

        # Country flag for high-spam-originating countries (informational)
        if ($orig->{country} && $orig->{country} =~ /^(?:CN|RU|NG|VN|IN|PK|BD)$/) {
            $flag->('INFO', 'high_spam_country',
                "Sending IP is in " . _country_name($orig->{country}) .
                " ($orig->{country}) — statistically high spam volume country");
        }
    }

    # ---- Authentication checks ----
    my $auth = $self->_parse_auth_results_cached();
    if (defined $auth->{spf} && $auth->{spf} !~ /^pass/i) {
        $flag->('HIGH', 'spf_fail',
            "SPF result: $auth->{spf} — sending IP not authorised by domain's SPF record");
    }
    if (defined $auth->{dkim} && $auth->{dkim} !~ /^pass/i) {
        $flag->('HIGH', 'dkim_fail',
            "DKIM result: $auth->{dkim} — message signature invalid or absent");
    }
    if (defined $auth->{dmarc} && $auth->{dmarc} !~ /^pass/i) {
        $flag->('HIGH', 'dmarc_fail',
            "DMARC result: $auth->{dmarc}");
    }

    # ---- Header identity checks ----
    # From: display name spoofing another domain
    my $from_raw = $self->_header_value('from') // '';
    my $from_decoded = $self->_decode_mime_words($from_raw);
    if ($from_decoded =~ /^"?([^"<]+?)"?\s*<([^>]+)>/) {
        my ($display, $addr) = ($1, $2);
        # Extract domains from display name
        while ($display =~ /\b([\w-]+\.(?:com|net|org|io|co|uk|au|gov|edu))\b/gi) {
            my $disp_domain = lc $1;
            my ($addr_domain) = $addr =~ /\@([\w.-]+)/;
            $addr_domain = lc($addr_domain // '');
            my $reg_disp = _registrable($disp_domain);
            my $reg_addr = _registrable($addr_domain);
            if ($reg_disp && $reg_addr && $reg_disp ne $reg_addr) {
                $flag->('HIGH', 'display_name_domain_spoof',
                    "From: display name mentions '$disp_domain' but actual address is <$addr> — classic impersonation technique");
            }
        }
    }

    # From: is a free webmail provider
    if ($from_raw =~ /\@(gmail|yahoo|hotmail|outlook|live|aol|mail\.ru|protonmail|yandex)\./i) {
        $flag->('MEDIUM', 'free_webmail_sender',
            "Message sent from free webmail address ($from_raw) — no corporate mail infrastructure");
    }

    # Reply-To differs from From:
    my $reply_to = $self->_header_value('reply-to');
    if ($reply_to) {
        my ($from_addr)  = $from_raw =~ /([\w.+%-]+\@[\w.-]+)/;
        my ($reply_addr) = $reply_to =~ /([\w.+%-]+\@[\w.-]+)/;
        if ($from_addr && $reply_addr &&
            lc($from_addr) ne lc($reply_addr)) {
            $flag->('MEDIUM', 'reply_to_differs_from_from',
                "Reply-To ($reply_addr) differs from From: ($from_addr) — replies will go to a different address");
        }
    }

    # To: is undisclosed-recipients or missing
    my $to = $self->_header_value('to') // '';
    if ($to =~ /undisclosed|:;/ || $to eq '') {
        $flag->('MEDIUM', 'undisclosed_recipients',
            "To: header is '$to' — message was bulk-sent with hidden recipient list");
    }

    # Subject encoded to hide content from filters
    my $subj_raw = $self->_header_value('subject') // '';
    if ($subj_raw =~ /=\?[^?]+\?[BQ]\?/i) {
        $flag->('LOW', 'encoded_subject',
            "Subject line is MIME-encoded: '$subj_raw' (decoded: '" .
            $self->_decode_mime_words($subj_raw) . "')");
    }

    # ---- URL checks ----
    my (%shortener_seen, %url_host_seen);
    for my $u ($self->embedded_urls()) {
        # URL shorteners
        my $bare = lc $u->{host};
        $bare =~ s/^www\.//;
        if ($URL_SHORTENERS{$bare} && !$shortener_seen{$bare}++) {
            $flag->('MEDIUM', 'url_shortener',
                "$u->{host} is a URL shortener — the real destination is hidden");
        }
        # HTTP not HTTPS
        if ($u->{url} =~ m{^http://}i && !$url_host_seen{ $u->{host} }++) {
            $flag->('LOW', 'http_not_https',
                "$u->{host} linked over plain HTTP — no encryption");
        }
    }

    # ---- Domain checks ----
    for my $d ($self->mailto_domains()) {
        if ($d->{recently_registered}) {
            $flag->('HIGH', 'recently_registered_domain',
                "$d->{domain} was registered $d->{registered} (less than 180 days ago)");
        }
	        if ($d->{expires}) {
            my $exp       = $self->_parse_date_to_epoch($d->{expires});
            my $now       = time();
            if ($exp) {
                my $remaining = $exp - $now;
                if ($remaining > 0 && $remaining < 30 * 86400) {
        # Domain expires very soon (< 30 days) — throwaway domain
                $flag->('HIGH', 'domain_expires_soon',
                    "$d->{domain} expires $d->{expires} — may be a throwaway domain");
                }
                elsif ($remaining <= 0) {
        # Domain already expired
                $flag->('HIGH', 'domain_expired',
                    "$d->{domain} expired $d->{expires} — domain has lapsed");
                }
            }
        }
        # Lookalike domain (contains well-known brand name but isn't it)
        for my $brand (qw(paypal apple google amazon microsoft netflix ebay
                          instagram facebook twitter linkedin bankofamerica
                          wellsfargo chase barclays hsbc lloyds santander)) {
            if ($d->{domain} =~ /\Q$brand\E/i &&
                $d->{domain} !~ /^\Q$brand\E\.(?:com|co\.uk|net|org)$/) {
                $flag->('HIGH', 'lookalike_domain',
                    "$d->{domain} contains brand name '$brand' but is not the real domain — possible phishing");
                last;
            }
        }
    }

    my $level = $score >= 9 ? 'HIGH'
              : $score >= 5 ? 'MEDIUM'
              : $score >= 2 ? 'LOW'
              :               'INFO';

    $self->{_risk} = { level => $level, score => $score, flags => \@flags };
    return $self->{_risk};
}

sub _parse_auth_results_cached {
    my ($self) = @_;
    return $self->{_auth_results} if $self->{_auth_results};
    my %auth;
    my $raw = join('; ',
        map { $_->{value} }
        grep { $_->{name} eq 'authentication-results' }
        @{ $self->{_headers} }
    );
    $auth{spf}   = $1 if $raw =~ /\bspf=(\S+)/i;
    $auth{dkim}  = $1 if $raw =~ /\bdkim=(\S+)/i;
    $auth{dmarc} = $1 if $raw =~ /\bdmarc=(\S+)/i;
    $auth{arc}   = $1 if $raw =~ /\barc=(\S+)/i;
    $self->{_auth_results} = \%auth;
    return \%auth;
}

sub _registrable {
    my ($host) = @_;
    return undef unless $host && $host =~ /\./;
    my @labels = split /\./, lc $host;
    return $host if @labels <= 2;
    if ($labels[-1] =~ /^[a-z]{2}$/ &&
        $labels[-2] =~ /^(?:co|com|net|org|gov|edu|ac|me)$/) {
        return join('.', @labels[-3..-1]);
    }
    return join('.', @labels[-2..-1]);
}

sub _country_name {
    my ($cc) = @_;
    my %names = ( CN => 'China', RU => 'Russia', NG => 'Nigeria',
                  VN => 'Vietnam', IN => 'India', PK => 'Pakistan',
                  BD => 'Bangladesh' );
    return $names{$cc} // $cc;
}

# -----------------------------------------------------------------------
# Public: ready-to-send abuse report text
# -----------------------------------------------------------------------

=head2 abuse_report_text()

Returns a string suitable for pasting into an abuse report email.
It includes the risk summary, the key findings, and the full original
message headers.

    my $report = $analyser->abuse_report_text();
    # Then email to each address from $analyser->abuse_contacts()

=cut

sub abuse_report_text {
    my ($self) = @_;
    my @out;

    push @out, "This is an automated abuse report generated by Mail::Message::Abuse.";
    push @out, "Please investigate the following spam/phishing message.";
    push @out, "";

    my $risk = $self->risk_assessment();
    push @out, "RISK LEVEL: $risk->{level} (score: $risk->{score})";
    push @out, "";

    if (@{ $risk->{flags} }) {
        push @out, "RED FLAGS IDENTIFIED:";
        for my $f (@{ $risk->{flags} }) {
            push @out, "  [$f->{severity}] $f->{detail}";
        }
        push @out, "";
    }

    my $orig = $self->originating_ip();
    if ($orig) {
        push @out, "ORIGINATING IP: $orig->{ip} ($orig->{rdns})";
        push @out, "NETWORK OWNER:  $orig->{org}";
        push @out, "";
    }

    my @contacts = $self->abuse_contacts();
    if (@contacts) {
        push @out, "ABUSE CONTACTS:";
        push @out, "  $_->{address} ($_->{role})" for @contacts;
        push @out, "";
    }

    push @out, "-" x 72;
    push @out, "ORIGINAL MESSAGE HEADERS:";
    push @out, "-" x 72;
    # Emit only the headers (not the body) to keep report concise
    for my $h (@{ $self->{_headers} }) {
        push @out, "$h->{name}: $h->{value}";
    }
    push @out, "";

    return join("\n", @out);
}

# -----------------------------------------------------------------------
# Public: consolidated abuse contact list
# -----------------------------------------------------------------------

=head2 abuse_contacts()

Returns a de-duplicated list of hashrefs, one per party that should
receive an abuse report, in priority order:

    {
        role    => 'Sending ISP',          # human-readable role
        address => 'abuse@senderisp.example',
        note    => 'IP block 120.88.0.0/14 owner',
        via     => 'ip-whois',             # ip-whois | domain-whois | provider-table | rdap
    }

Roles produced (in order):

  Sending ISP       - network owner of the originating IP
  URL host          - network owner of each unique web-server IP
  Mail host (MX)    - network owner of the domain's MX record IP
  DNS host (NS)     - network owner of the authoritative NS IP
  Domain registrar  - registrar abuse contact from domain WHOIS
  Account provider  - e.g. Gmail / Outlook for the From: account

Addresses are deduplicated so the same address never appears twice,
even if it is discovered through multiple routes.

=cut

sub abuse_contacts {
	my ($self) = @_;
	my (@contacts, %seen);

	my $add = sub {
		my %args = @_;
		my $addr = lc($args{address} // '');

		return unless $addr && $addr =~ /\@/;
		return if $seen{$addr}++;
		push @contacts, \%args;
	};

    # 1. Sending ISP (originating IP)
    my $orig = $self->originating_ip();
    if ($orig) {
        my $pa = $self->_provider_abuse_for_ip($orig->{ip}, $orig->{rdns});
        if ($pa) {
            $add->(role    => 'Sending ISP (provider table)',
                   address => $pa->{email},
                   note    => "$orig->{ip} ($orig->{rdns}) — $pa->{note}",
                   via     => 'provider-table');
        }
        if ($orig->{abuse} && $orig->{abuse} ne '(unknown)') {
            $add->(role    => 'Sending ISP',
                   address => $orig->{abuse},
                   note    => "Network owner of originating IP $orig->{ip} ($orig->{org})",
                   via     => 'ip-whois');
        }
    }

    # 2. URL hosts
    my (%url_host_seen);
    for my $u ($self->embedded_urls()) {
        next if $url_host_seen{ $u->{host} }++;
        my $pa = $self->_provider_abuse_for_host($u->{host});
        if ($pa) {
            $add->(role    => "URL host (provider table)",
                   address => $pa->{email},
                   note    => "$u->{host} — $pa->{note}",
                   via     => 'provider-table');
        }
        if ($u->{abuse} && $u->{abuse} ne '(unknown)') {
            $add->(role    => 'URL host',
                   address => $u->{abuse},
                   note    => "Hosting $u->{host} ($u->{ip}, $u->{org})",
                   via     => 'ip-whois');
        }
    }

    # 3. Contact/reply domains — web host, MX, NS, registrar, From: account
    for my $d ($self->mailto_domains()) {
        my $dom = $d->{domain};

        # Web host
        if ($d->{web_abuse}) {
            my $pa = $self->_provider_abuse_for_host($dom);
            if ($pa) {
                $add->(role    => "Web host of $dom (provider table)",
                       address => $pa->{email},
                       note    => $pa->{note},
                       via     => 'provider-table');
            }
            $add->(role    => "Web host of $dom",
                   address => $d->{web_abuse},
                   note    => "Hosting $dom ($d->{web_ip}, $d->{web_org})",
                   via     => 'ip-whois');
        }

        # MX host
        if ($d->{mx_abuse}) {
            $add->(role    => "Mail host (MX) for $dom",
                   address => $d->{mx_abuse},
		   note => sprintf('MX %s (%s, %s)',
			    $d->{mx_host} // '(unknown host)',
			    $d->{mx_ip}   // '(unknown IP)',
			    $d->{mx_org}  // '(unknown org)'),
                   via     => 'ip-whois');
        }

        # NS host
        if ($d->{ns_abuse}) {
            $add->(role    => "DNS host (NS) for $dom",
                   address => $d->{ns_abuse},
		   note => sprintf('NS %s (%s, %s)',
			    $d->{ns_host} // '(unknown host)',
			    $d->{ns_ip}   // '(unknown IP)',
			    $d->{ns_org}  // '(unknown org)'),
                   via     => 'ip-whois');
        }

        # Domain registrar
        if ($d->{registrar_abuse}) {
            $add->(role    => "Domain registrar for $dom",
                   address => $d->{registrar_abuse},
                   note    => "Registrar: $d->{registrar}",
                   via     => 'domain-whois');
        }
    }

    # 4. From: / Reply-To: / Return-Path: account provider
    for my $hname (qw(from reply-to return-path)) {
        my $val = $self->_header_value($hname) // next;
        my ($addr_domain) = $val =~ /\@([\w.-]+)/;
        next unless $addr_domain;
        my $pa = $self->_provider_abuse_for_host($addr_domain);
        if ($pa) {
            $add->(role    => "Account provider ($hname: $val)",
                   address => $pa->{email},
                   note    => $pa->{note},
                   via     => 'provider-table');
        }
    }

	return @contacts;
}

# Look up provider abuse contact by plain domain name
sub _provider_abuse_for_host {
    my ($self, $host) = @_;
    $host = lc $host;
    # Try exact match, then strip successive subdomains
    while ($host =~ /\./) {
        return $PROVIDER_ABUSE{$host} if $PROVIDER_ABUSE{$host};
        $host =~ s/^[^.]+\.//;
    }
    return undef;
}

# Look up provider abuse contact by IP and/or rDNS hostname
sub _provider_abuse_for_ip {
    my ($self, $ip, $rdns) = @_;
    return $self->_provider_abuse_for_host($rdns) if $rdns;
    return undef;
}

# -----------------------------------------------------------------------
# Public: report
# -----------------------------------------------------------------------

=head2 report()

Returns a formatted plain-text abuse report.

=cut

sub report {
    my ($self) = @_;
    my @out;

    push @out, "=" x 72;
    push @out, "  Mail::Message::Abuse Report  (v$VERSION)";
    push @out, "=" x 72;
    push @out, "";

    # ---- envelope summary ----
    for my $f (qw(from reply-to return-path subject date message-id)) {
        my $v = $self->_header_value($f);
        next unless defined $v;
        my $decoded = $self->_decode_mime_words($v);
        my $label   = ucfirst($f);
        push @out, sprintf("  %-14s : %s", $label,
            $decoded ne $v ? "$decoded  [encoded: $v]" : $v);
    }
    push @out, "";

    # ---- risk assessment ----
    my $risk = $self->risk_assessment();
    push @out, "[ RISK ASSESSMENT: $risk->{level} (score: $risk->{score}) ]";
    if (@{ $risk->{flags} }) {
        for my $f (@{ $risk->{flags} }) {
            push @out, "  [$f->{severity}] $f->{detail}";
        }
    } else {
        push @out, "  (no specific red flags detected)";
    }
    push @out, "";

    # ---- originating host ----
    push @out, "[ ORIGINATING HOST ]";
    my $orig = $self->originating_ip();
    if ($orig) {
        push @out, "  IP           : $orig->{ip}";
        push @out, "  Reverse DNS  : $orig->{rdns}"       if $orig->{rdns};
        push @out, "  Country      : $orig->{country}"    if $orig->{country};
        push @out, "  Organisation : $orig->{org}"         if $orig->{org};
        push @out, "  Abuse addr   : $orig->{abuse}"       if $orig->{abuse};
        push @out, "  Confidence   : $orig->{confidence}";
        push @out, "  Note         : $orig->{note}"        if $orig->{note};
    } else {
        push @out, "  (could not determine originating IP)";
    }
    push @out, "";

    # ---- HTTP/HTTPS URLs ----
    push @out, "[ EMBEDDED HTTP/HTTPS URLs ]";
    my @urls = $self->embedded_urls();
    if (@urls) {
        # Group by hostname so host/IP/org is shown once,
        # with all distinct paths listed beneath it
        my (%host_order, %host_meta, %host_paths);
        my $seq = 0;
        for my $u (@urls) {
            my $h = $u->{host};
            unless (exists $host_order{$h}) {
                $host_order{$h} = $seq++;
                $host_meta{$h}  = { ip => $u->{ip}, org => $u->{org},
                                    abuse => $u->{abuse}, country => $u->{country} };
            }
            push @{ $host_paths{$h} }, $u->{url};
        }

        for my $h (sort { $host_order{$a} <=> $host_order{$b} } keys %host_order) {
            my $m    = $host_meta{$h};
            my $bare = lc $h; $bare =~ s/^www\.//;
            push @out, "  Host         : $h" .
                       ($URL_SHORTENERS{$bare} ? '  *** URL SHORTENER — real destination hidden ***' : '');
            push @out, "  IP           : $m->{ip}"    if $m->{ip};
            push @out, "  Country      : $m->{country}" if $m->{country};
            push @out, "  Organisation : $m->{org}"   if $m->{org};
            push @out, "  Abuse addr   : $m->{abuse}" if $m->{abuse};
            my @paths = @{ $host_paths{$h} };
            if (@paths == 1) {
                push @out, "  URL          : $paths[0]";
            } else {
                push @out, "  URLs (" . scalar(@paths) . ")     :";
                push @out, "    $_" for @paths;
            }
            push @out, "";
        }
    } else {
        push @out, "  (none found)";
        push @out, "";
    }

    # ---- contact / reply domains ----
    push @out, "[ CONTACT / REPLY-TO DOMAINS ]";
    my @mdoms = $self->mailto_domains();
    if (@mdoms) {
        for my $d (@mdoms) {
            push @out, "  Domain       : $d->{domain}";
            push @out, "  Found in     : $d->{source}";

            if ($d->{recently_registered}) {
                push @out, "  *** WARNING: RECENTLY REGISTERED - possible phishing domain ***";
            }
            push @out, "  Registered   : $d->{registered}" if $d->{registered};
            push @out, "  Expires      : $d->{expires}"     if $d->{expires};
            push @out, "  Registrar    : $d->{registrar}"         if $d->{registrar};
            push @out, "  Reg. abuse   : $d->{registrar_abuse}"   if $d->{registrar_abuse};

            if ($d->{web_ip}) {
                push @out, "  Web host IP  : $d->{web_ip}";
                push @out, "  Web host org : $d->{web_org}"   if $d->{web_org};
                push @out, "  Web abuse    : $d->{web_abuse}" if $d->{web_abuse};
            } else {
                push @out, "  Web host     : (no A record / unreachable)";
            }

            if ($d->{mx_host}) {
                push @out, "  MX host      : $d->{mx_host}";
                push @out, "  MX IP        : $d->{mx_ip}"    if $d->{mx_ip};
                push @out, "  MX org       : $d->{mx_org}"   if $d->{mx_org};
                push @out, "  MX abuse     : $d->{mx_abuse}" if $d->{mx_abuse};
            } else {
                push @out, "  MX host      : (none found)";
            }

            if ($d->{ns_host}) {
                push @out, "  NS host      : $d->{ns_host}";
                push @out, "  NS IP        : $d->{ns_ip}"    if $d->{ns_ip};
                push @out, "  NS org       : $d->{ns_org}"   if $d->{ns_org};
                push @out, "  NS abuse     : $d->{ns_abuse}" if $d->{ns_abuse};
            }

            push @out, "";
        }
    } else {
        push @out, "  (none found)";
        push @out, "";
    }

    # ---- Abuse contacts summary ----
    push @out, "[ WHERE TO SEND ABUSE REPORTS ]";
    my @contacts = $self->abuse_contacts();
    if (@contacts) {
        for my $c (@contacts) {
            push @out, "  Role         : $c->{role}";
            push @out, "  Send to      : $c->{address}";
            push @out, "  Note         : $c->{note}" if $c->{note};
            push @out, "  Discovered   : $c->{via}";
            push @out, "";
        }
    } else {
        push @out, "  (no abuse contacts could be determined)";
        push @out, "";
    }

    push @out, "=" x 72;
    return join("\n", @out) . "\n";
}

# -----------------------------------------------------------------------
# Private: message parsing
# -----------------------------------------------------------------------

sub _split_message {
    my ($self, $text) = @_;

    my ($header_block, $body_raw) = split /\r?\n\r?\n/, $text, 2;
    $body_raw //= '';

    # Unfold continuation lines (RFC 2822 s2.2.3)
    $header_block =~ s/\r?\n([ \t]+)/ $1/g;

    my @headers;
    for my $line (split /\r?\n/, $header_block) {
        if ($line =~ /^([\w-]+)\s*:\s*(.*)/) {
            push @headers, { name => lc($1), value => $2 };
        }
    }
    $self->{_headers}  = \@headers;
    $self->{_received} = [ map  { $_->{value} }
                           grep { $_->{name} eq 'received' } @headers ];

    my ($ct_h)  = grep { $_->{name} eq 'content-type' }              @headers;
    my ($cte_h) = grep { $_->{name} eq 'content-transfer-encoding' } @headers;
    my $ct  = defined $ct_h  ? $ct_h->{value}  : '';
    my $cte = defined $cte_h ? $cte_h->{value} : '';

    if ($ct =~ /multipart/i) {
        my ($boundary) = $ct =~ /boundary="?([^";]+)"?/i;
        $self->_decode_multipart($body_raw, $boundary) if $boundary;
    } else {
        my $decoded = $self->_decode_body($body_raw, $cte);
        if ($ct =~ /html/i) { $self->{_body_html}  = $decoded }
        else                 { $self->{_body_plain} = $decoded }
    }

    $self->_debug(sprintf "Parsed %d headers, %d Received lines",
        scalar @headers, scalar @{ $self->{_received} });
}

sub _decode_multipart {
    my ($self, $body, $boundary) = @_;

    my @parts = split /--\Q$boundary\E(?:--)?/, $body;
    for my $part (@parts) {
        next unless $part =~ /\S/;
        $part =~ s/^\r?\n//;

        my ($phdr_block, $pbody) = split /\r?\n\r?\n/, $part, 2;
        next unless defined $pbody;

        $phdr_block =~ s/\r?\n([ \t]+)/ $1/g;
        my %phdr;
        for my $line (split /\r?\n/, $phdr_block) {
            $phdr{ lc($1) } = $2 if $line =~ /^([\w-]+)\s*:\s*(.*)/;
        }

        my $pct  = $phdr{'content-type'}              // '';
        my $pcte = $phdr{'content-transfer-encoding'} // '';
        my $decoded = $self->_decode_body($pbody, $pcte);

        if    ($pct =~ /text\/html/i)  { $self->{_body_html}  .= $decoded }
        elsif ($pct =~ /text/i || !$pct) { $self->{_body_plain} .= $decoded }
    }
}

sub _decode_body {
    my ($self, $body, $cte) = @_;
    $cte //= '';
    return decode_qp($body)     if $cte =~ /quoted-printable/i;
    return decode_base64($body) if $cte =~ /base64/i;
    return $body;
}

# -----------------------------------------------------------------------
# Private: Received-chain -> originating IP
# -----------------------------------------------------------------------

sub _find_origin {
    my ($self) = @_;
    my @candidates;

    for my $hdr (reverse @{ $self->{_received} }) {
        my $ip = $self->_extract_ip_from_received($hdr) // next;
        next if $self->_is_private($ip);
        next if $self->_is_trusted($ip);
        push @candidates, $ip;
    }

    unless (@candidates) {
        my $xoip = $self->_header_value('x-originating-ip');
        if ($xoip) {
            $xoip =~ s/[\[\]\s]//g;
            return $self->_enrich_ip($xoip, 'low',
                'Taken from X-Originating-IP (webmail, unverified)')
                unless $self->_is_private($xoip);
        }
        return undef;
    }

    return $self->_enrich_ip(
        $candidates[0],
        @candidates > 1 ? 'high' : 'medium',
        'First external hop in Received: chain',
    );
}

sub _extract_ip_from_received {
    my ($self, $hdr) = @_;
    for my $re (@RECEIVED_IP_RE) {
        if ($hdr =~ $re) {
            my $ip = $1;
            next unless $ip =~ /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/;
            next if grep { $_ > 255 } split /\./, $ip;
            return $ip;
        }
    }
    return undef;
}

sub _is_private {
    my ($self, $ip) = @_;
    return 1 unless defined $ip && $ip ne '';
    for my $re (@PRIVATE_RANGES) { return 1 if $ip =~ $re }
    return 0;
}

sub _is_trusted {
    my ($self, $ip) = @_;
    for my $cidr (@{ $self->{trusted_relays} }) {
        return 1 if $self->_ip_in_cidr($ip, $cidr);
    }
    return 0;
}

# -----------------------------------------------------------------------
# Private: HTTP/HTTPS URL extraction
# -----------------------------------------------------------------------

sub _extract_and_resolve_urls {
    my ($self) = @_;
    my (%url_seen, %host_cache);
    my @results;
    my $combined = $self->{_body_plain} . "\n" . $self->{_body_html};

    for my $url ($self->_extract_http_urls($combined)) {
        next if $url_seen{$url}++;
        my ($host) = $url =~ m{https?://([^/:?\s#]+)}i;
        next unless $host;

        # Resolve and WHOIS once per unique hostname, then cache
        unless (exists $host_cache{$host}) {
            my $ip    = $self->_resolve_host($host) // '(unresolved)';
            my $whois = $ip ne '(unresolved)' ? $self->_whois_ip($ip) : {};
            $host_cache{$host} = {
                ip      => $ip,
                org     => $whois->{org}     // '(unknown)',
                abuse   => $whois->{abuse}   // '(unknown)',
                country => $whois->{country} // undef,
            };
        }

        push @results, {
            url   => $url,
            host  => $host,
            %{ $host_cache{$host} },
        };
    }
    return \@results;
}

sub _extract_http_urls {
    my ($self, $body) = @_;
    my @urls;

    if ($HAS_HTML_LINKEXTOR) {
        my $p = HTML::LinkExtor->new(sub {
            my ($tag, %attrs) = @_;
            for my $attr (qw(href src action)) {
                push @urls, $attrs{$attr}
                    if ($attrs{$attr} // '') =~ m{^https?://}i;
            }
        });
        $p->parse($body);
    }

    while ($body =~ m{(https?://[^\s<>"'\)\]]+)}gi) {
        push @urls, $1;
    }

    my %seen;
    my @all = grep { !$seen{$_}++ } @urls;
    s/[.,;:!?\)>\]]+$// for @all;
    return @all;
}

# -----------------------------------------------------------------------
# Private: domain extraction and full analysis
# -----------------------------------------------------------------------

sub _extract_and_analyse_domains {
    my ($self) = @_;
    my %seen;
    my @domains_with_source;

    my $record = sub {
        my ($dom, $source) = @_;
        $dom = lc $dom;
        $dom =~ s/\.$//;
        return if $TRUSTED_DOMAINS{$dom};
        return if $seen{$dom}++;
        push @domains_with_source, { domain => $dom, source => $source };
    };

    # Header fields that may carry contact domains
    my %header_sources = (
        'from'         => 'From: header',
        'reply-to'     => 'Reply-To: header',
        'return-path'  => 'Return-Path: header',
    );
    for my $hname (sort keys %header_sources) {
        my $val = $self->_header_value($hname) // next;
        $record->($_, $header_sources{$hname})
            for $self->_domains_from_text($val);
    }

    # Body (plain + HTML)
    my $combined = $self->{_body_plain} . "\n" . $self->{_body_html};
    $record->($_, 'email address / mailto in body')
        for $self->_domains_from_text($combined);

    # Analyse each domain
    my @results;
    for my $entry (@domains_with_source) {
        my $info = $self->_analyse_domain($entry->{domain});
        push @results, { %$entry, %$info };
    }
    return \@results;
}

# Extract unique domains from mailto: links and bare user@domain addresses
sub _domains_from_text {
    my ($self, $text) = @_;
    my %seen;
    my @out;

    # mailto:user@domain  (handles HTML-entity = from quoted-printable)
    while ($text =~ /mailto:(?:[^@\s<>"]+)@([\w.-]+)/gi) {
        my $dom = lc $1;  $dom =~ s/\.$//;
        push @out, $dom unless $seen{$dom}++;
    }

    # bare user@domain
    while ($text =~ /\b[\w.+%-]+@([\w.-]+\.[a-zA-Z]{2,})\b/g) {
        my $dom = lc $1;  $dom =~ s/\.$//;
        push @out, $dom unless $seen{$dom}++;
    }

    return @out;
}

# Full domain intelligence gathering
sub _analyse_domain {
    my ($self, $domain) = @_;
    return $self->{_domain_info}{$domain}
        if $self->{_domain_info}{$domain};

    $self->_debug("Analysing domain: $domain");
    my %info;

    # --- A record -> web hosting ---
    my $web_ip = $self->_resolve_host($domain);
    if ($web_ip) {
        $info{web_ip} = $web_ip;
        my $w = $self->_whois_ip($web_ip);
        $info{web_org}   = $w->{org}   if $w->{org};
        $info{web_abuse} = $w->{abuse} if $w->{abuse};
    }

    if ($HAS_NET_DNS) {
        my $res = Net::DNS::Resolver->new(
            tcp_timeout => $self->{timeout},
            udp_timeout => $self->{timeout},
        );

        # --- MX record -> mail hosting ---
        my $mxq = $res->search($domain, 'MX');
        if ($mxq) {
            my ($best) = sort { $a->preference <=> $b->preference }
                         grep { $_->type eq 'MX' } $mxq->answer;
            if ($best) {
                (my $mx_host = lc $best->exchange) =~ s/\.$//;
                $info{mx_host} = $mx_host;
                my $mx_ip = $self->_resolve_host($mx_host);
                if ($mx_ip) {
                    $info{mx_ip} = $mx_ip;
                    my $mw = $self->_whois_ip($mx_ip);
                    $info{mx_org}   = $mw->{org}   if $mw->{org};
                    $info{mx_abuse} = $mw->{abuse} if $mw->{abuse};
                }
            }
        }

        # --- NS record -> DNS hosting ---
        my $nsq = $res->search($domain, 'NS');
        if ($nsq) {
            my ($first) = grep { $_->type eq 'NS' } $nsq->answer;
            if ($first) {
                (my $ns_host = lc $first->nsdname) =~ s/\.$//;
                $info{ns_host} = $ns_host;
                my $ns_ip = $self->_resolve_host($ns_host);
                if ($ns_ip) {
                    $info{ns_ip} = $ns_ip;
                    my $nw = $self->_whois_ip($ns_ip);
                    $info{ns_org}   = $nw->{org}   if $nw->{org};
                    $info{ns_abuse} = $nw->{abuse} if $nw->{abuse};
                }
            }
        }
    }

    # --- Domain WHOIS -> registrar + dates ---
    my $domain_whois = $self->_domain_whois($domain);
    if ($domain_whois) {
        $info{whois_raw} = substr($domain_whois, 0, 2048);

        if ($domain_whois =~ /Registrar:\s*(.+)/i) {
            ($info{registrar} = $1) =~ s/\s+$//;
        }

        # Registrar abuse contact email
        for my $pat (
            qr/Registrar Abuse Contact Email:\s*(\S+@\S+)/i,
            qr/Abuse Contact Email:\s*(\S+@\S+)/i,
            qr/abuse-contact:\s*(\S+@\S+)/i,
        ) {
            if (!$info{registrar_abuse} && $domain_whois =~ $pat) {
                ($info{registrar_abuse} = $1) =~ s/\s+$//;
            }
        }

        for my $pat (
            qr/Creation Date:\s*(\S+)/i,
            qr/Created(?:\s+On)?:\s*(\S+)/i,
            qr/Registration Time:\s*(\S+)/i,
            qr/registered:\s*(\S+)/i,
        ) {
            if (!$info{registered} && $domain_whois =~ $pat) {
                ($info{registered} = $1) =~ s/[TZ].*//;
            }
        }

        for my $pat (
            qr/Registry Expiry Date:\s*(\S+)/i,
            qr/Expir(?:y|ation)(?: Date)?:\s*(\S+)/i,
            qr/paid-till:\s*(\S+)/i,
        ) {
            if (!$info{expires} && $domain_whois =~ $pat) {
                ($info{expires} = $1) =~ s/[TZ].*//;
            }
        }

        # Flag recently registered domains (common phishing indicator)
        if ($info{registered}) {
            my $epoch = $self->_parse_date_to_epoch($info{registered});
            $info{recently_registered} = 1
                if $epoch && (time() - $epoch) < 180 * 86400;
        }
    }

    $self->{_domain_info}{$domain} = \%info;
    return \%info;
}

# -----------------------------------------------------------------------
# Private: DNS helpers
# -----------------------------------------------------------------------

sub _resolve_host {
    my ($self, $host) = @_;
    return $host if $host =~ /^\d{1,3}(?:\.\d{1,3}){3}$/;

    if ($HAS_NET_DNS) {
        my $res   = Net::DNS::Resolver->new(
            tcp_timeout => $self->{timeout},
            udp_timeout => $self->{timeout},
        );
        my $query = $res->search($host, 'A');
        if ($query) {
            for my $rr ($query->answer) {
                return $rr->address if $rr->type eq 'A';
            }
        }
        return undef;
    }

    my $packed = eval { inet_aton($host) };
    return $packed ? inet_ntoa($packed) : undef;
}

sub _reverse_dns {
    my ($self, $ip) = @_;
    return undef unless $ip;

    if ($HAS_NET_DNS) {
        my $res   = Net::DNS::Resolver->new(tcp_timeout => $self->{timeout});
        my $query = $res->search($ip, 'PTR');
        if ($query) {
            for my $rr ($query->answer) {
                return $rr->ptrdname if $rr->type eq 'PTR';
            }
        }
        return undef;
    }

    return scalar gethostbyaddr(inet_aton($ip), Socket::AF_INET());
}

# -----------------------------------------------------------------------
# Private: WHOIS / RDAP
# -----------------------------------------------------------------------

# IP WHOIS: RDAP preferred, raw WHOIS TCP fallback
sub _whois_ip {
    my ($self, $ip) = @_;
    my $result = $HAS_LWP ? $self->_rdap_lookup($ip) : {};
    unless ($result->{org}) {
        my $raw = $self->_raw_whois($ip, 'whois.iana.org');
        if ($raw) {
            my ($ref) = $raw =~ /whois:\s*([\w.-]+)/i;
            my $detail = $ref ? $self->_raw_whois($ip, $ref) : $raw;
            $result = $self->_parse_whois_text($detail) if $detail;
        }
    }
    return $result;
}

# Domain WHOIS: ask IANA for the TLD's whois server, then query it
sub _domain_whois {
    my ($self, $domain) = @_;
    my $iana = $self->_raw_whois($domain, 'whois.iana.org') // return undef;
    my ($server) = $iana =~ /whois:\s*([\w.-]+)/i;
    return undef unless $server;
    return $self->_raw_whois($domain, $server);
}

sub _rdap_lookup {
    my ($self, $ip) = @_;
    return {} unless $HAS_LWP;
    my $ua  = LWP::UserAgent->new(timeout => $self->{timeout},
                                  agent   => "Mail-Message-Abuse/$VERSION");
    my $res = eval { $ua->get("https://rdap.arin.net/registry/ip/$ip") };
    return {} unless $res && $res->is_success;
    my $j = $res->decoded_content;
    my %info;
    $info{org}    = $1 if $j =~ /"name"\s*:\s*"([^"]+)"/;
    $info{handle} = $1 if $j =~ /"handle"\s*:\s*"([^"]+)"/;
    if ($j =~ /"abuse".*?"email"\s*:\s*"([^"]+)"/s) {
        $info{abuse} = $1;
    } elsif ($j =~ /"email"\s*:\s*"([^@"]+@[^"]+)"/) {
        $info{abuse} = $1;
    }
    # Country code from RDAP
    $info{country} = $1 if $j =~ /"country"\s*:\s*"([A-Z]{2})"/;
    return \%info;
}

sub _raw_whois {
    my ($self, $query, $server) = @_;
    $server //= 'whois.iana.org';
    $self->_debug("WHOIS $server -> $query");
    my $sock = eval {
        IO::Socket::INET->new(
            PeerAddr => $server,
            PeerPort => 43,
            Proto    => 'tcp',
            Timeout  => $self->{timeout},
        );
    };
    return undef unless $sock;
    print $sock "$query\r\n";
    my $response = '';
    eval {
        local $SIG{ALRM} = sub { die "timeout\n" };
        alarm($self->{timeout});
        while (my $line = <$sock>) { $response .= $line }
        alarm(0);
    };
    alarm(0);
    close $sock;
    return $response || undef;
}

sub _parse_whois_text {
    my ($self, $text) = @_;
    return {} unless $text;
    my %info;
    for my $pat (
        qr/^OrgName:\s*(.+)/mi,   qr/^org-name:\s*(.+)/mi,
        qr/^owner:\s*(.+)/mi,     qr/^descr:\s*(.+)/mi,
    ) {
        if (!$info{org} && $text =~ $pat) {
            ($info{org} = $1) =~ s/\s+$//;
        }
    }
    for my $pat (
        qr/OrgAbuseEmail:\s*(\S+@\S+)/mi,
        qr/abuse-mailbox:\s*(\S+@\S+)/mi,
    ) {
        if (!$info{abuse} && $text =~ $pat) {
            ($info{abuse} = $1) =~ s/\s+$//;
        }
    }
    $info{abuse} //= $1 if $text =~ /(abuse\@[\w.-]+)/i;
    # Country
    $info{country} = $1
        if $text =~ /^country:\s*([A-Z]{2})\s*$/mi;
    return \%info;
}

# -----------------------------------------------------------------------
# Private: utilities
# -----------------------------------------------------------------------

sub _enrich_ip {
    my ($self, $ip, $confidence, $note) = @_;
    my $rdns  = $self->_reverse_dns($ip);
    my $whois = $self->_whois_ip($ip);
    return {
        ip         => $ip,
        rdns       => $rdns  // '(no reverse DNS)',
        org        => $whois->{org}     // '(unknown)',
        abuse      => $whois->{abuse}   // '(unknown)',
        country    => $whois->{country} // undef,
        confidence => $confidence,
        note       => $note,
    };
}

sub _header_value {
	my ($self, $name) = @_;
	for my $h (@{ $self->{_headers} }) {
		return $h->{value} if $h->{name} eq lc($name);
	}
	return undef;
}

sub _ip_in_cidr {
    my ($self, $ip, $cidr) = @_;
    return $ip eq $cidr unless $cidr =~ m{/};
    my ($net_addr, $prefix) = split m{/}, $cidr;
    my $mask  = ~0 << (32 - $prefix);
    my $net_n = unpack 'N', (inet_aton($net_addr) // return 0);
    my $ip_n  = unpack 'N', (inet_aton($ip)       // return 0);
    return ($ip_n & $mask) == ($net_n & $mask);
}

# Lightweight date-to-epoch for common WHOIS date formats:
#   2024-11-01   2024-11-01T12:00:00Z   01-Nov-2024
sub _parse_date_to_epoch {
    my ($self, $str) = @_;
    return undef unless $str;
    my %mon = ( jan=>1,feb=>2,mar=>3,apr=>4,may=>5,jun=>6,
                jul=>7,aug=>8,sep=>9,oct=>10,nov=>11,dec=>12 );
    my ($y, $m, $d);
    if    ($str =~ /^(\d{4})-(\d{2})-(\d{2})/)         { ($y,$m,$d)=($1,$2,$3) }
    elsif ($str =~ /^(\d{2})-([A-Za-z]{3})-(\d{4})/)   { ($d,$m,$y)=($1,$mon{lc$2}//0,$3) }
    elsif ($str =~ /^(\d{2})\/(\d{2})\/(\d{4})/)        { ($m,$d,$y)=($1,$2,$3) }
    return undef unless $y && $m && $d;
    if (eval { require Time::Local; 1 }) {
        return eval { Time::Local::timegm(0,0,0,$d,$m-1,$y-1900) };
    }
    return ($y-1970)*365.25*86400 + ($m-1)*30.5*86400 + ($d-1)*86400;
}

sub _debug {
	my ($self, $msg) = @_;
	print STDERR "[Mail::Message::Abuse] $msg\n" if $self->{verbose};
}

1;

__END__

=head1 ALGORITHM: DOMAIN INTELLIGENCE PIPELINE

For each unique non-infrastructure domain found in the email, the module
runs the following pipeline:

    Domain name
        |
        +-- A record  --> web hosting IP  --> RDAP --> org + abuse contact
        |
        +-- MX record --> mail server hostname --> A --> RDAP --> org + abuse
        |
        +-- NS record --> nameserver hostname  --> A --> RDAP --> org + abuse
        |
        +-- WHOIS (TLD whois server via IANA referral)
               +-- Registrar name
               +-- Creation date  (-> recently-registered flag if < 180 days)
               +-- Expiry date

=head1 WHY WEB HOSTING != MAIL HOSTING != DNS HOSTING

A fraudster registering C<sminvestmentsupplychain.com> might:

=over 4

=item * Register the domain at GoDaddy (registrar)

=item * Point the NS records at Cloudflare (DNS/CDN)

=item * Have no web server at all (A record absent)

=item * Route the MX records to Google Workspace or similar

=back

Each of these parties has an abuse contact, and each can independently
take action to disrupt the spam/phishing operation.  The module reports
all of them separately.

=head1 RECENTLY-REGISTERED FLAG

Phishing domains are very commonly registered hours or days before the
spam run.  The module flags any domain whose WHOIS creation date is
less than 180 days ago with C<recently_registered =E<gt> 1>.

=head1 SEE ALSO

L<Net::DNS>, L<LWP::UserAgent>, L<HTML::LinkExtor>, L<MIME::QuotedPrint>

SpamCop: L<https://www.spamcop.net/>
ARIN RDAP: L<https://rdap.arin.net/>

=head1 LICENSE

Same terms as Perl itself (Artistic 2.0 / GPL v1+).

=cut
