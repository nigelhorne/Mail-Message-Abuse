# NAME

Mail::Message::Abuse - Analyse spam email to identify originating hosts,
hosted URLs, and suspicious domains

# SYNOPSIS

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

# DESCRIPTION

`Mail::Message::Abuse` examines the raw source of a spam/phishing e-mail
and answers the questions abuse investigators ask:

- 1. Where did the message really come from?

    Walks the `Received:` chain, skips private/trusted IPs, and identifies the
    first external hop.  Enriches with rDNS, WHOIS/RDAP org name and abuse
    contact.

- 2. Who hosts the advertised web sites?

    Extracts every `http://` and `https://` URL from both plain-text and HTML
    parts, resolves each hostname to an IP, and looks up the network owner.

- 3. Who owns the reply-to / contact domains?

    Extracts domains from `mailto:` links, bare e-mail addresses in the body,
    the `From:`/`Reply-To:`/`Sender:`/`Return-Path:` headers, `DKIM-Signature: d=`
    (the signing domain), `List-Unsubscribe:` (the ESP or bulk-sender domain), and the
    `Message-ID:` domain.  For each unique domain it gathers:

    - Domain registrar and registrant (WHOIS)
    - Web-hosting IP and network owner (A record -> RDAP)
    - Mail-hosting IP and network owner (MX record -> RDAP)
    - DNS nameserver operator (NS record -> RDAP)
    - Whether the domain was recently registered (potential flag)

# REQUIRED MODULES

    Net::DNS
    LWP::UserAgent
    HTML::LinkExtor
    Socket
    IO::Socket::INET
    MIME::QuotedPrint  (core since Perl 5.8)
    MIME::Base64       (core since Perl 5.8)

All are available from CPAN.

# METHODS

## new( %options )

    my $a = Mail::Message::Abuse->new(
        timeout        => 15,
        trusted_relays => ['203.0.113.0/24'],
        verbose        => 0,
    );

## parse\_email( $text )

Feed the raw RFC 2822 source to the analyser.  Accepts a scalar or
scalar-ref.  Handles `multipart`, `quoted-printable`, and `base64`
bodies automatically.

## originating\_ip()

Returns a hashref:

    {
        ip         => '209.85.218.67',
        rdns       => 'mail-ej1-f67.google.com',
        org        => 'Google LLC',
        abuse      => 'network-abuse@google.com',
        confidence => 'high',
        note       => 'First external hop in Received: chain',
    }

## embedded\_urls()

Returns a list of hashrefs for every HTTP/HTTPS URL in the body:

    {
        url   => 'https://spamsite.example/offer',
        host  => 'spamsite.example',
        ip    => '198.51.100.7',
        org   => 'Dodgy Hosting Ltd',
        abuse => 'abuse@dodgy.example',
    }

## mailto\_domains()

Returns a list of hashrefs, one per unique non-infrastructure domain found
in `mailto:` links, bare e-mail addresses in the body, and the envelope /
header fields `From:`, `Reply-To:`, `Sender:`, `Return-Path:`,
`DKIM-Signature: d=` (signing domain), `List-Unsubscribe:` (ESP domain),
and the domain portion of `Message-ID:`.

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

## all\_domains()

Union of every domain seen across HTTP URLs and mailto/reply domains.

## sending\_software()

Returns a list of hashrefs identifying software or infrastructure
clues extracted from the email headers.  Each entry has:

    {
        header => 'X-PHP-Originating-Script',
        value  => '1000:newsletter.php',
        note   => 'PHP script on shared hosting — report to hosting abuse team',
    }

Headers examined: `X-Mailer`, `User-Agent`, `X-PHP-Originating-Script`,
`X-Source`, `X-Source-Args`, `X-Source-Host`.

## received\_trail()

Returns a list of hashrefs, one per `Received:` header (oldest first),
each containing the extracted IP, envelope recipient (`for` clause), and
the server's internal tracking ID (`id` clause).  These are the tracking
identifiers a receiving ISP's abuse team needs to look up the mail session
in their logs.

    (
      { received => '...raw header...', ip => '1.2.3.4',
        for => 'victim@example.com', id => 'ABC123' },
      ...
    )

## risk\_assessment()

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
              detail => 'bit.ly used — real destination hidden' },
            ...
        ],
    }

## abuse\_report\_text()

Returns a string suitable for pasting into an abuse report email.
It includes the risk summary, the key findings, and the full original
message headers.

    my $report = $analyser->abuse_report_text();
    # Then email to each address from $analyser->abuse_contacts()

## abuse\_contacts()

Returns a de-duplicated list of hashrefs, one per party that should
receive an abuse report, in priority order:

    {
        role    => 'Sending ISP',          # human-readable role
        address => 'abuse@senderisp.example',
        note    => 'IP block 120.88.0.0/14 owner',
        via     => 'ip-whois',             # ip-whois | domain-whois | provider-table | rdap
    }

Roles produced (in order):

    Sending ISP            — network owner of the originating IP
    URL host               — network owner of each unique web-server IP
    Mail host (MX)         — network owner of the domain's MX record IP
    DNS host (NS)          — network owner of the authoritative NS IP
    Domain registrar       — registrar abuse contact from domain WHOIS
    Account provider       — e.g. Gmail / Outlook for the From:/Sender: account
    DKIM signer            — the organisation whose key signed the message
    ESP / bulk sender      — identified via List-Unsubscribe: domain

Addresses are deduplicated so the same address never appears twice,
even if it is discovered through multiple routes.

## report()

Returns a formatted plain-text abuse report.

# ALGORITHM: DOMAIN INTELLIGENCE PIPELINE

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
               +-- Registrar name + abuse contact
               +-- Creation date  (-> recently-registered flag if < 180 days)
               +-- Expiry date    (-> expires-soon or expired flags)

Domains are collected from:

    From:/Reply-To:/Sender:/Return-Path: headers
    DKIM-Signature: d=  (signing domain)
    List-Unsubscribe:   (ESP / bulk sender domain)
    Message-ID:         (often reveals real sending platform)
    mailto: links and bare addresses in the body

# WHY WEB HOSTING != MAIL HOSTING != DNS HOSTING

A fraudster registering `sminvestmentsupplychain.com` might:

- Register the domain at GoDaddy (registrar)
- Point the NS records at Cloudflare (DNS/CDN)
- Have no web server at all (A record absent)
- Route the MX records to Google Workspace or similar

Each of these parties has an abuse contact, and each can independently
take action to disrupt the spam/phishing operation.  The module reports
all of them separately.

# RECENTLY-REGISTERED FLAG

Phishing domains are very commonly registered hours or days before the
spam run.  The module flags any domain whose WHOIS creation date is
less than 180 days ago with `recently_registered => 1`.

# SEE ALSO

[Net::DNS](https://metacpan.org/pod/Net%3A%3ADNS), [LWP::UserAgent](https://metacpan.org/pod/LWP%3A%3AUserAgent), [HTML::LinkExtor](https://metacpan.org/pod/HTML%3A%3ALinkExtor), [MIME::QuotedPrint](https://metacpan.org/pod/MIME%3A%3AQuotedPrint)

ARIN RDAP: [https://rdap.arin.net/](https://rdap.arin.net/)

# LICENSE

Same terms as Perl itself (Artistic 2.0 / GPL v1+).

# POD ERRORS

Hey! **The above document had some coding errors, which are explained below:**

- Around line 441:

    Non-ASCII character seen before =encoding in '—'. Assuming UTF-8
