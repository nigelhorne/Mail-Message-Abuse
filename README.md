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

### Purpose

Constructs and returns a new `Mail::Message::Abuse` analyser object.  The
object is stateless until `parse_email()` is called; all analysis results
are stored on the object and retrieved via the public accessor methods
documented below.

A single object may be reused for multiple emails by calling `parse_email()`
again: all cached state from the previous message is discarded automatically.

### Usage

    # Minimal -- all options take safe defaults
    my $analyser = Mail::Message::Abuse->new();

    # With options
    my $analyser = Mail::Message::Abuse->new(
        timeout        => 15,
        trusted_relays => ['203.0.113.0/24', '10.0.0.0/8'],
        verbose        => 0,
    );

    $analyser->parse_email($raw_rfc2822_text);
    my $origin   = $analyser->originating_ip();
    my @urls     = $analyser->embedded_urls();
    my @domains  = $analyser->mailto_domains();
    my $risk     = $analyser->risk_assessment();
    my @contacts = $analyser->abuse_contacts();
    print $analyser->report();

### Arguments

All arguments are optional named parameters passed as a flat key-value list.

- `timeout` (integer, default 10)

    Maximum number of seconds to wait for any single network operation: DNS
    lookups, WHOIS TCP connections, and RDAP HTTP requests each respect this
    limit independently.  Set to 0 to disable timeouts (not recommended for
    production use).  Values must be non-negative integers.

- `trusted_relays` (arrayref of strings, default \[\])

    A list of IP addresses or CIDR blocks that are under your own
    administrative control and should be excluded from the Received: chain
    analysis.  Any hop whose IP matches an entry here is skipped when
    determining `originating_ip()`.

    Each element may be:

    - An exact IPv4 address: `'192.0.2.1'`
    - A CIDR block: `'192.0.2.0/24'`, `'10.0.0.0/8'`

    Use this to exclude your own mail relays, load balancers, and internal
    infrastructure so they are never mistaken for the spam origin.

    Example: if your inbound gateway at 203.0.113.5 adds a Received: header
    before passing the message to your mail server, pass
    `trusted_relays => ['203.0.113.5']` and that hop will be ignored.

- `verbose` (boolean, default 0)

    When true, diagnostic messages are written to STDERR as the object
    processes each email.  Messages are prefixed with `[Mail::Message::Abuse]`
    and describe each major analysis step (header parsing, DNS resolution,
    WHOIS queries, etc.).  Intended for development and debugging; leave false
    in production.

### Returns

A blessed `Mail::Message::Abuse` object.  The object is immediately usable;
no network I/O is performed during construction.

### Side Effects

None.  The constructor performs no I/O.  All network activity is deferred
until the first call to a method that requires it (`originating_ip()`,
`embedded_urls()`, `mailto_domains()`, or any method that calls them).

### Notes

- The `timeout` option uses `//` (defined-or), so `timeout => 0` is
stored correctly as zero.  All other constructor options also use `//`.
- Unknown option keys are silently ignored.
- The object is not thread-safe.  If you process multiple emails
concurrently, construct a separate `Mail::Message::Abuse` object per
thread or per-request.
- The `alarm()` mechanism used by the raw WHOIS client is not reliable on
Windows or inside threaded Perl interpreters.  All other functionality
works on those platforms; only WHOIS TCP connections may not respect the
timeout on affected platforms.

### API Specification

#### Input

    # Params::Validate::Strict compatible specification
    {
        timeout => {
            type     => SCALAR,
            regex    => qr/^\d+$/,
            optional => 1,
            default  => 10,
        },
        trusted_relays => {
            type     => ARRAYREF,
            optional => 1,
            default  => [],
            # Each element: exact IPv4 address or CIDR in the form a.b.c.d/n
            # where n is an integer in the range 0..32
        },
        verbose => {
            type     => SCALAR,
            regex    => qr/^[01]$/,
            optional => 1,
            default  => 0,
        },
    }

#### Output

    # Return::Set compatible specification
    {
        type  => 'Mail::Message::Abuse',  # blessed object
        isa   => 'Mail::Message::Abuse',

        # Guaranteed slots on the returned object (public API):
        #   timeout        => non-negative integer
        #   trusted_relays => arrayref of strings
        #   verbose        => 0 or 1
        #
        # All other slots are private (_raw, _headers, etc.) and
        # must not be accessed or modified by the caller.
    }

## parse\_email( $text )

### Purpose

Feeds a raw RFC 2822 email message to the analyser and prepares it for
subsequent interrogation.  This is the only method that must be called
before any other public method; all analysis is driven by the message
supplied here.

If the same object is used for a second message, calling `parse_email()`
again completely replaces all state from the first message.  No trace of
the previous email survives.

### Usage

    # From a scalar
    my $raw = do { local $/; <STDIN> };
    $analyser->parse_email($raw);

    # From a scalar reference (avoids copying large messages)
    $analyser->parse_email(\$raw);

    # Chained with new()
    my $analyser = Mail::Message::Abuse->new()->parse_email($raw);

    # Re-use the same object for multiple messages
    while (my $msg = $queue->next()) {
        $analyser->parse_email($msg->raw_text());
        my $risk = $analyser->risk_assessment();
        report_if_spam($analyser) if $risk->{level} ne 'INFO';
    }

### Arguments

- `$text` (scalar or scalar reference, required)

    The complete raw source of the email message as it arrived at your MTA,
    including all headers and the body, exactly as transferred over the wire.
    Both LF-only and CRLF line endings are accepted and handled transparently.

    A scalar reference is accepted as an alternative to a plain scalar.  The
    referent is dereferenced internally; the original variable is not modified.

    The following body encodings are decoded automatically:

    - `quoted-printable` (Content-Transfer-Encoding: quoted-printable)
    - `base64` (Content-Transfer-Encoding: base64)
    - `7bit` / `8bit` / `binary` (passed through as-is)

    Multipart messages (`multipart/alternative`, `multipart/mixed`, etc.)
    are split on their boundary and each text part decoded according to its
    own Content-Transfer-Encoding.  Non-text parts (attachments, inline images)
    are silently skipped.

### Returns

The object itself (`$self`), allowing method chaining:

    my $origin = Mail::Message::Abuse->new()->parse_email($raw)->originating_ip();

### Side Effects

The following work is performed synchronously, with no network I/O:

- Header parsing

    All RFC 2822 headers are parsed into an internal list.  Folded (multi-line)
    header values are unfolded per RFC 2822 section 2.2.3.  The `Received:`
    chain is extracted separately for origin analysis.  Header names are
    normalised to lower-case.  When duplicate headers are present, all copies
    are retained; accessor methods return the first occurrence.

- Body decoding

    The message body is decoded according to its Content-Transfer-Encoding and
    stored as plain text (`_body_plain`) and/or HTML (`_body_html`).
    Multipart messages have each qualifying part appended in order.

- Sending software extraction

    The headers `X-Mailer`, `User-Agent`, `X-PHP-Originating-Script`,
    `X-Source`, `X-Source-Args`, and `X-Source-Host` are extracted if
    present and stored for retrieval via `sending_software()`.

- Received chain tracking data

    Each `Received:` header is scanned for an IP address, an envelope
    recipient (`for <addr@domain.com>`), and a server tracking ID
    (`id token`).  Results are stored for retrieval via `received_trail()`,
    ordered oldest hop first.

- Cache invalidation

    All lazily-computed results from a previous call to `parse_email()` on
    the same object are discarded: `originating_ip()`, `embedded_urls()`,
    `mailto_domains()`, `risk_assessment()`, and the authentication-results
    cache are all reset to `undef` so the next call to any of them analyses
    the new message from scratch.

All network I/O (DNS lookups, WHOIS/RDAP queries) is deferred; it occurs
only when a caller first invokes `originating_ip()`, `embedded_urls()`,
or `mailto_domains()`.

### Notes

- If `$text` is an empty string, contains only whitespace, or contains no
header/body separator, the method returns `$self` without populating any
internal state.  All public methods will return empty lists, `undef`, or
safe zero-value results rather than dying.
- The raw text is stored verbatim (in `_raw`) and is reproduced in the
output of `abuse_report_text()`.  For very large messages this doubles
the memory used.  If memory is a concern, supply a scalar reference so at
least the method argument does not copy the string on the call stack.
- HTML bodies are stored separately from plain-text bodies.  URL and
email-address extraction runs across both.  A URL that appears only in the
HTML part and not in the plain-text part is still reported.
- Decoding errors in base64 or quoted-printable payloads are silenced; the
partially-decoded or raw bytes are used in place of correct output.  This
prevents malformed spam from causing exceptions during analysis.

### API Specification

#### Input

    # Params::Validate::Strict compatible specification
    # (positional argument, not named)
    [
        {
            type => SCALAR | SCALARREF,
            # SCALAR:    the complete raw email text
            # SCALARREF: reference to the complete raw email text;
            #            the referent must be a defined string
            # Both LF and CRLF line endings are accepted.
        },
    ]

#### Output

    # Return::Set compatible specification
    {
        type => 'Mail::Message::Abuse',  # the invocant, returned for chaining
        isa  => 'Mail::Message::Abuse',

        # Guaranteed post-conditions on the returned object:
        #   sending_software()  returns a (possibly empty) list
        #   received_trail()    returns a (possibly empty) list
        #   All lazy-analysis caches are reset (undef or empty)
        #   _raw contains the verbatim input text
    }

## originating\_ip()

### Purpose

Identifies the IP address of the machine that originally injected the
message into the mail system, as opposed to any intermediate relay that
passed it along.  This is the address of the spammer's machine, their ISP's
outbound mail server, or a compromised host -- the primary target for an
ISP abuse report.

The method walks the `Received:` chain from oldest to newest, skips every
hop whose IP is in a private, reserved, or trusted range, and returns the
first remaining (external) IP, enriched with reverse DNS, network ownership,
and abuse contact information gathered via rDNS, RDAP, and WHOIS.

If no usable IP can be found in the `Received:` chain, the method falls back
to the `X-Originating-IP` header injected by some webmail providers.

The result is computed once and cached; subsequent calls on the same object
return the same hashref without repeating any network I/O.

### Usage

    $analyser->parse_email($raw);
    my $orig = $analyser->originating_ip();

    if (defined $orig) {
        printf "Origin: %s (%s)\n",   $orig->{ip},  $orig->{rdns};
        printf "Owner:  %s\n",        $orig->{org};
        printf "Abuse:  %s\n",        $orig->{abuse};
        printf "Confidence: %s\n",    $orig->{confidence};
    } else {
        print "Could not determine originating IP.\n";
    }

    # Confidence-gated reporting
    if (defined $orig && $orig->{confidence} eq 'high') {
        send_abuse_report($orig->{abuse}, $analyser->abuse_report_text());
    }

### Arguments

None.  `parse_email()` must have been called first.

### Returns

    {
      ip         => '209.85.218.67',
      rdns       => 'mail-ej1-f67.google.com',
      org        => 'Google LLC',
      abuse      => 'network-abuse@google.com',
      confidence => 'high',
      note       => 'First external hop in Received: chain',
    }

On success, a hashref with the following keys (all always present):

- `ip` (string)

    The dotted-quad IPv4 address of the identified originating host.

- `rdns` (string)

    The reverse DNS (PTR) hostname for `ip`.  Set to the literal string
    `'(no reverse DNS)'` if no PTR record exists or the lookup fails.
    The presence and format of rDNS is used by `risk_assessment()` to detect
    residential broadband senders.

- `org` (string)

    The network organisation name that owns the IP block, sourced from RDAP
    (preferred) or WHOIS (fallback).  Set to `'(unknown)'` if neither source
    returns an organisation name.

- `abuse` (string)

    The abuse contact email address for the IP block owner, sourced from RDAP
    or WHOIS.  Set to `'(unknown)'` if no abuse address can be determined.
    `abuse_contacts()` uses this field when building the contact list; entries
    with the value `'(unknown)'` are suppressed.

- `confidence` (string)

    One of three values reflecting how reliably the IP was identified:

    - `'high'`

        Two or more distinct external hops were found in the `Received:` chain
        (after removing private and trusted IPs).  The bottom-most hop is reported.
        A chain of two or more external hops is strong evidence the first-seen IP
        is the true origin.

    - `'medium'`

        Exactly one external hop was found in the `Received:` chain.  The IP is
        likely correct but cannot be independently corroborated by a relay record.

    - `'low'`

        No usable IP was found in the `Received:` chain; the IP was taken from the
        `X-Originating-IP` header instead.  This header is injected by webmail
        interfaces and is not verifiable; a sender can forge it.

- `note` (string)

    A human-readable explanation of how the IP was selected.  Examples:

        'First external hop in Received: chain'
        'Taken from X-Originating-IP (webmail, unverified)'

- `country` (string or undef)

    The two-letter ISO 3166-1 alpha-2 country code for the IP block, sourced
    from RDAP or WHOIS.  `undef` if no country code is available.
    `risk_assessment()` uses this field to raise the `high_spam_country` flag
    for a set of statistically high-volume spam-originating countries.

Returns `undef` if no suitable originating IP can be determined (no
`Received:` headers, all IPs are private or trusted, no usable
`X-Originating-IP` header, or `parse_email()` has not been called).

### Side Effects

The first call (or the first call after a `parse_email()`) performs the
following network I/O, subject to the `timeout` set at construction:

- One PTR (rDNS) lookup for the identified IP address.
- One RDAP query to `rdap.arin.net` (if `LWP::UserAgent` is available).
- If RDAP returns no organisation: one WHOIS query to `whois.iana.org`
to obtain the authoritative registry, followed by one WHOIS query to that
registry.

All subsequent calls return the cached hashref.  The cache is invalidated by
`parse_email()`.

### Algorithm: Received: chain traversal

The `Received:` headers are walked from bottom (oldest) to top (most
recent).  For each header, the first IPv4 address is extracted in priority
order:

- 1. A bracketed address: `[1.2.3.4]`
- 2. A parenthesised address: `(hostname [1.2.3.4])`
- 3. An address following `from hostname`
- 4. Any bare dotted-quad as a last resort

An extracted IP is discarded if it:

- Falls in any of the following excluded ranges: 0.0.0.0/8 (RFC 1122),
127.0.0.0/8 (loopback), 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16
(RFC 1918), 169.254.0.0/16 (link-local), 100.64.0.0/10 (CGN, RFC 6598),
192.0.0.0/24, 192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24 (RFC 5737
documentation ranges), 255.0.0.0/8 (broadcast), or IPv6 loopback/ULA.
- Matches any entry in the `trusted_relays` list passed to `new()`.
- Contains an octet greater than 255 (i.e., is syntactically invalid).

All non-discarded IPs are collected; the first (oldest) one is reported as
the origin.  The count of non-discarded IPs determines the confidence level.

### Notes

- Only IPv4 addresses are extracted.  IPv6 addresses in `Received:` headers
are ignored.  This is a known limitation; most spam still travels via IPv4
infrastructure.
- The algorithm trusts the `Received:` headers as written.  A sophisticated
sender who controls an intermediate relay can insert a forged `Received:`
header with an arbitrary IP.  The `confidence` field reflects this: `high`
confidence requires two independent external hops but cannot guarantee that
neither hop forged its Received: line.
- If all `Received:` IPs are private or trusted, the `X-Originating-IP`
header is used as a fallback.  This header is unverifiable and receives
`confidence` `'low'`.  Brackets and whitespace are stripped from its
value before use.
- The `country` key is `undef`, not the empty string, when no country code
is available.  Test with `defined $orig->{country}`, not a boolean
check.
- `org` and `abuse` default to the literal string `'(unknown)'`, not
`undef`.  This means they are always defined; use string equality to test
for the unknown case: `$orig->{abuse} eq '(unknown)'`.

### API Specification

#### Input

    # Params::Validate::Strict compatible specification
    # No arguments; invocant must be a Mail::Message::Abuse object
    # on which parse_email() has previously been called.
    []

#### Output

    # Return::Set compatible specification

    # On success:
    {
        type => HASHREF,
        keys => {
            ip => {
                type  => SCALAR,
                regex => qr/^\d{1,3}(?:\.\d{1,3}){3}$/,  # dotted-quad IPv4
            },
            rdns => {
                type  => SCALAR,
                # hostname string, or the literal '(no reverse DNS)'
            },
            org => {
                type  => SCALAR,
                # organisation name, or the literal '(unknown)'
            },
            abuse => {
                type  => SCALAR,
                # email address, or the literal '(unknown)'
            },
            confidence => {
                type  => SCALAR,
                regex => qr/^(?:high|medium|low)$/,
            },
            note => {
                type => SCALAR,
            },
            country => {
                type     => SCALAR,
                optional => 1,  # present but may be undef
                regex    => qr/^[A-Z]{2}$/,
            },
        },
    }

    # On failure (no usable IP found):
    undef

## embedded\_urls()

### Purpose

Extracts every HTTP and HTTPS URL from the message body and enriches each
one with the hosting IP address, network organisation name, abuse contact,
and country code of the web server it points to.

URL extraction runs across both the plain-text and HTML parts of the
message.  When `HTML::LinkExtor` is available, HTML `href`, `src`, and
`action` attributes are parsed structurally; a plain-text regex pass then
catches any remaining bare URLs in both parts.

Each unique URL is returned as a separate hashref.  When multiple distinct
URLs share the same hostname, DNS resolution and WHOIS are performed only
once for that hostname; all URLs on that host share the cached result.

The result list is computed once and cached; subsequent calls on the same
object return the same data without repeating any network I/O.

### Usage

    $analyser->parse_email($raw);
    my @urls = $analyser->embedded_urls();

    if (@urls) {
        for my $u (@urls) {
            printf "URL:   %s\n", $u->{url};
            printf "Host:  %s  IP: %s\n", $u->{host}, $u->{ip};
            printf "Owner: %s\n", $u->{org};
            printf "Abuse: %s\n", $u->{abuse};
            print  "\n";
        }
    } else {
        print "No HTTP/HTTPS URLs found.\n";
    }

    # Collect unique abuse contacts from URL hosts
    my %seen;
    my @url_contacts = grep { !$seen{$_}++ }
                       map  { $_->{abuse} }
                       grep { $_->{abuse} ne '(unknown)' }
                       @urls;

    # Check for URL shorteners
    my @shorteners = grep { $_->{host} =~ /bit\.ly|tinyurl/i } @urls;
    warn "Message contains URL shortener(s)\n" if @shorteners;

### Arguments

None.  `parse_email()` must have been called first.

### Returns

A list (not an arrayref) of hashrefs, one per unique URL found in the body,
in the order they were first encountered.  Returns an empty list if the body
contains no HTTP or HTTPS URLs, or if `parse_email()` has not been called.

    {
        url   => 'https://spamsite.example/offer',
        host  => 'spamsite.example',
        ip    => '198.51.100.7',
        org   => 'Dodgy Hosting Ltd',
        abuse => 'abuse@dodgy.example',
    }

Each hashref contains the following keys (all always present):

- `url` (string)

    The complete URL as it appeared in the message body, with any trailing
    punctuation characters (`.`, `,`, `;`, `:`, `!`, `?`, `)`, `>`,
    `]`) stripped.  The scheme is preserved in the original case (`HTTP://`,
    `https://`, etc.).

- `host` (string)

    The hostname portion of the URL, extracted from between the scheme and
    the first `/`, `?`, `:`, `#`, or whitespace character.  Port numbers
    are not included.  Examples: `'www.example.com'`, `'bit.ly'`.

- `ip` (string)

    The IPv4 address the hostname resolved to at analysis time.  Set to the
    literal string `'(unresolved)'` if DNS resolution failed or returned no
    A record.  Note that short-lived spam infrastructure may resolve differently
    at report time than at analysis time.

- `org` (string)

    The network organisation that owns the IP block, from RDAP or WHOIS.
    Set to `'(unknown)'` if no organisation name is available or if the host
    could not be resolved.

- `abuse` (string)

    The abuse contact email address for the IP block owner, from RDAP or WHOIS.
    Set to `'(unknown)'` if no abuse address is available or if the host could
    not be resolved.  `abuse_contacts()` uses this field; entries with the
    value `'(unknown)'` are suppressed in the contact list.

- `country` (string or undef)

    The two-letter ISO 3166-1 alpha-2 country code for the IP block, from RDAP
    or WHOIS.  `undef` if no country code is available or if the host could
    not be resolved.

### Side Effects

The first call (or first call after `parse_email()`) performs network I/O
for each unique hostname found, subject to the `timeout` set at construction.
For each unique hostname:

- One A record (DNS) lookup to resolve the hostname to an IP address.
- If resolution succeeds: one RDAP query to `rdap.arin.net`
(if `LWP::UserAgent` is available).
- If RDAP returns no organisation: one WHOIS query to `whois.iana.org`
followed by one query to the authoritative registry for the IP block.

DNS and WHOIS are performed at most once per unique hostname per
`parse_email()` call, regardless of how many distinct URLs share that
hostname.  All subsequent calls return the cached list.  The cache is
invalidated by `parse_email()`.

### Algorithm: URL extraction

URLs are extracted from the concatenation of the decoded plain-text body
and the decoded HTML body, in that order.  The two extraction passes are:

- 1. Structural HTML parsing (if `HTML::LinkExtor` is installed)

    `href`, `src`, and `action` attributes of all HTML tags are inspected.
    Any value beginning with `http://` or `https://` (case-insensitive) is
    collected.  This correctly handles URLs that contain characters which would
    confuse a plain-text regex, such as embedded spaces in quoted attribute
    values.

- 2. Plain-text regex pass

    A greedy regex `https?://[^\s<`"'\\)\\\]\]+> is applied to the combined body
    text.  This catches bare URLs in plain-text parts and any URLs not captured
    by the structural pass.

After both passes, the combined list is deduplicated (preserving first-seen
order) and trailing punctuation is stripped from each URL.  The host is
then extracted and used as a cache key for DNS and WHOIS lookups.

### Notes

- Only `http://` and `https://` URLs are extracted.  `ftp://`, `mailto:`,
and other schemes are not included.  Bare domain names without a scheme are
also not included (those are handled by `mailto_domains()`).
- Duplicate URLs -- the same complete URL string appearing more than once --
are reported only once.  Two URLs that differ only in case (e.g.
`HTTP://` vs `https://`) are treated as distinct.
- If a hostname appears in multiple distinct URLs, all URLs are returned
individually as separate hashrefs, but the `ip`, `org`, `abuse`, and
`country` fields are identical across all of them (copied from the single
cached lookup).  Callers grouping by host should use the `host` field
as the key.
- `ip`, `org`, and `abuse` use sentinel strings rather than `undef` for
the unknown case: `'(unresolved)'` for `ip` when DNS fails, `'(unknown)'`
for `org` and `abuse` when WHOIS returns nothing.  Only `country` is
`undef` in the unknown case.  Test accordingly:
`$u->{ip} ne '(unresolved)'`, not `defined $u->{ip}`.
- URL shorteners (`bit.ly`, `tinyurl.com`, and several dozen others) are
detected by `risk_assessment()`, which raises a `url_shortener` flag.
`embedded_urls()` itself does not filter them out; they appear in the
returned list so their hosting information can still be reported.
- The order of URLs in the returned list reflects first-seen order across
both the plain-text and HTML extraction passes.  Because the HTML parser
and the regex run over the same combined string, a URL that appears in
both an HTML attribute and as bare text will appear only once (at the
position it was first seen).

### API Specification

#### Input

    # Params::Validate::Strict compatible specification
    # No arguments.
    []

#### Output

    # Return::Set compatible specification

    # A list (possibly empty) of hashrefs:
    (
        {
            type => HASHREF,
            keys => {
                url => {
                    type  => SCALAR,
                    regex => qr{^https?://}i,
                },
                host => {
                    type  => SCALAR,
                    # hostname without port; no leading scheme
                },
                ip => {
                    type  => SCALAR,
                    # dotted-quad IPv4, or the literal '(unresolved)'
                },
                org => {
                    type  => SCALAR,
                    # organisation name, or the literal '(unknown)'
                },
                abuse => {
                    type  => SCALAR,
                    # email address, or the literal '(unknown)'
                },
                country => {
                    type     => SCALAR,
                    optional => 1,  # present but may be undef
                    regex    => qr/^[A-Z]{2}$/,
                },
            },
        },
        # ... one hashref per unique URL, in first-seen order
    )

    # Empty list when no HTTP/HTTPS URLs are present in the body.

## mailto\_domains()

### Purpose

Identifies every domain associated with the message as a contact, reply,
or delivery address, then runs a full intelligence pipeline on each one to
determine who hosts its web server, who handles its mail, who operates its
DNS, and who registered it.

This answers POD description item 3: "Who owns the reply-to / contact
domains?"  A spammer may use one sending IP but route replies through an
entirely different organisation's infrastructure.  This method surfaces all
of those parties so each can be contacted independently.

The result is computed once and cached; subsequent calls on the same object
return the same list without repeating any network I/O.

### Usage

    $analyser->parse_email($raw);
    my @domains = $analyser->mailto_domains();

    for my $d (@domains) {
        printf "Domain : %s  (found in %s)\n", $d->{domain}, $d->{source};
        printf "  Web  : %s  owned by %s\n",   $d->{web_ip}  // 'none',
                                                $d->{web_org} // 'unknown';
        printf "  MX   : %s\n", $d->{mx_host} // 'none';
        printf "  Reg  : %s  (registered %s)\n", $d->{registrar}  // 'unknown',
                                                  $d->{registered} // 'unknown';
        if ($d->{recently_registered}) {
            print  "  *** RECENTLY REGISTERED -- possible phishing domain ***\n";
        }
        print "\n";
    }

    # Collect registrar abuse contacts
    my @reg_contacts = map  { $_->{registrar_abuse} }
                       grep { defined $_->{registrar_abuse} }
                       @domains;

    # Find recently registered domains
    my @fresh = grep { $_->{recently_registered} } @domains;

### Arguments

None.  `parse_email()` must have been called first.

### Returns

A list (not an arrayref) of hashrefs, one per unique non-infrastructure
domain, in the order each domain was first encountered across all sources.
Returns an empty list if no qualifying domains are found, or if
`parse_email()` has not been called.

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

Each hashref contains the following keys.  Keys marked "(optional)" are
absent from the hashref when the corresponding information is unavailable;
test with `exists $d->{key}` or `defined $d->{key}` as
appropriate.

- `domain` (string, always present)

    The domain name, lower-cased and with any trailing dot removed.  This is
    the full domain as it appeared in the source header or body (e.g.
    `'sminvestmentsupplychain.com'`), not the registrable eTLD+1.

- `source` (string, always present)

    A human-readable label identifying which header or body section the domain
    was first seen in.  Possible values:

        'From: header'
        'Reply-To: header'
        'Return-Path: header'
        'Sender: header'
        'Message-ID: header'
        'DKIM-Signature: d= (signing domain)'
        'List-Unsubscribe: header'
        'email address / mailto in body'

    When a domain appears in multiple sources, only the first-seen source is
    recorded.

- `web_ip` (string, optional)

    The IPv4 address the domain's A record resolved to.  Absent if the domain
    has no A record or resolution failed.

- `web_org` (string, optional)

    The network organisation hosting the web server at `web_ip`, from RDAP or
    WHOIS.  Absent if `web_ip` is absent or WHOIS returns no organisation.

- `web_abuse` (string, optional)

    The abuse contact email for the web-hosting network, from RDAP or WHOIS.
    Absent if `web_ip` is absent or WHOIS returns no abuse address.

- `mx_host` (string, optional)

    The hostname of the lowest-preference MX record for the domain.
    Only populated when `Net::DNS` is installed.  Absent if no MX record
    exists or `Net::DNS` is unavailable.

- `mx_ip` (string, optional)

    The IPv4 address of the MX host.  Absent if `mx_host` is absent or
    the MX hostname could not be resolved.

- `mx_org` (string, optional)

    The network organisation hosting the MX server, from RDAP or WHOIS.

- `mx_abuse` (string, optional)

    The abuse contact email for the MX hosting network.

- `ns_host` (string, optional)

    The hostname of the first NS (nameserver) record returned for the domain.
    Only populated when `Net::DNS` is installed.

- `ns_ip` (string, optional)

    The IPv4 address of the NS host.

- `ns_org` (string, optional)

    The network organisation operating the nameserver, from RDAP or WHOIS.

- `ns_abuse` (string, optional)

    The abuse contact email for the nameserver network.

- `registrar` (string, optional)

    The registrar name as it appears in the domain's WHOIS record (e.g.
    `'GoDaddy.com LLC'`).  Absent if WHOIS is unavailable or the registrar
    field was not found.

- `registrar_abuse` (string, optional)

    The registrar's abuse contact email, extracted from the WHOIS record
    using the following patterns in priority order:
    `Registrar Abuse Contact Email:`, `Abuse Contact Email:`,
    `abuse-contact:`.  Absent if none of these fields is present.

- `registered` (string, optional)

    The domain's creation date as a string in `YYYY-MM-DD` form (ISO 8601
    date only, time and timezone stripped).  Parsed from WHOIS using the
    following field names in priority order: `Creation Date:`,
    `Created On:`, `Registration Time:`, `registered:`.
    Absent if WHOIS is unavailable or no creation date field is found.

- `expires` (string, optional)

    The domain's expiry date in `YYYY-MM-DD` form.  Parsed from:
    `Registry Expiry Date:`, `Expiry Date:`, `Expiration Date:`,
    `paid-till:`.  Absent if not found.

- `recently_registered` (integer 1, optional)

    Present and set to `1` when the domain's `registered` date is less
    than 180 days before the time of analysis.  Absent (not merely `0`) when
    the domain is not recently registered or when no creation date is available.
    Used by `risk_assessment()` to raise the `recently_registered_domain` flag.

- `whois_raw` (string, optional)

    The first 2048 bytes of the raw WHOIS response for the domain.  Intended
    for human inspection or logging.  Absent if WHOIS is unavailable or returns
    no data.

### Side Effects

The first call (or first call after `parse_email()`) performs network I/O
for each unique domain collected, subject to the `timeout` set at
construction.  For each domain:

- One A record (DNS) lookup for the domain itself (web hosting).
- If `Net::DNS` is installed: one MX record lookup; if an MX record
is found, one further A lookup for the MX hostname.
- If `Net::DNS` is installed: one NS record lookup; if an NS record
is found, one further A lookup for the NS hostname.
- For each resolved IP (web, MX, NS): one RDAP or WHOIS query to
identify the network owner.  The same IP is never queried twice.
- Two WHOIS queries for the domain itself: one to `whois.iana.org`
to obtain the TLD's authoritative registry, followed by one to that registry.

In the worst case (all records present, all IPs distinct, RDAP unavailable),
each domain incurs: 3 A lookups + 1 MX lookup + 1 NS lookup + 3 WHOIS IP
queries (6 TCP connections each) + 2 domain WHOIS queries (2 TCP connections)
&#x3d; up to 17 network operations.  In practice, shared hosting and cached DNS
reduce this considerably.

All results are cached per domain within a single `parse_email()` lifetime.
The cache is invalidated by `parse_email()`.

### Domain collection sources

Domains are collected from the following sources, in this order.  A domain
that appears in multiple sources is recorded only once, with the source
label of its first occurrence.

- 1. `From:`, `Reply-To:`, `Return-Path:`, `Sender:` headers

    All email addresses in these headers are parsed and their domain portions
    extracted.

- 2. `Message-ID:` header

    The domain portion of the Message-ID is extracted.  This often reveals the
    real bulk-sending platform even when `From:` is forged.  Domains that are
    members of the infrastructure exclusion list (`gmail.com`, `outlook.com`,
    `google.com`, `microsoft.com`, `apple.com`, `amazon.com`,
    `yahoo.com`, `googlemail.com`, `hotmail.com`) are skipped here, as are
    any domain whose registrable eTLD+1 is in that list (e.g. `mail.gmail.com`
    is excluded because `gmail.com` is in the list).

- 3. `DKIM-Signature: d=` tag

    The signing domain from the first `DKIM-Signature:` header.  This is the
    organisation that cryptographically vouches for the message, and is
    actionable regardless of whether DKIM passes or fails.

- 4. `List-Unsubscribe:` header

    Both `https://` URLs and `mailto:` addresses in this header are parsed.
    The domains identify the ESP or bulk sender responsible for delivery, who
    may be held accountable under CAN-SPAM and similar laws.

- 5. Body (plain-text and HTML)

    `mailto:` links and bare `user@domain` email addresses are extracted from
    the combined decoded body.  `mailto:` links are recognised even when the
    `@` sign is HTML-entity-encoded (`=40` or `=3D@`) from quoted-printable
    transfer.

In all cases, domain names are lower-cased, trailing dots are stripped, and
domains in the infrastructure exclusion list are silently discarded.

### Notes

- Unlike `embedded_urls()`, which reports the host of every URL, this method
reports the contact domain -- the domain a human would write to, not
necessarily the domain hosting the content.  A spam campaign might send
from `firmluminary.com` (contact domain) while linking to CDN URLs at
`cloudflare.com` (URL host).  Both are captured, by different methods.
- The `recently_registered` key is absent, not `0`, when a domain is not
recently registered or when no creation date is available.  Test for it with
`$d->{recently_registered}` (boolean truthiness), not with `eq '1'`.
- All hosting sub-keys (`web_ip`, `mx_host`, `ns_host`, etc.) are absent
rather than `undef` when the corresponding lookup yields no result.  This
means `keys %$d` will contain only the keys for which information was
actually found.  Do not assume any optional key is present.
- MX and NS lookups require `Net::DNS`.  If `Net::DNS` is not installed,
only A record and WHOIS information is populated; `mx_host`, `mx_ip`,
`mx_org`, `mx_abuse`, `ns_host`, `ns_ip`, `ns_org`, and `ns_abuse`
will all be absent for every domain.
- Date strings in `registered` and `expires` have the time and timezone
components stripped (everything from `T` or `Z` onward in ISO 8601 form).
They are stored as plain strings, not as epoch integers; use
`_parse_date_to_epoch()` (private) if a numeric comparison is needed.
- `whois_raw` is truncated to the first 2048 bytes of the raw WHOIS
response.  The date and registrar fields are parsed from the full response
before truncation, so truncation does not affect the structured fields.

### API Specification

#### Input

    # Params::Validate::Strict compatible specification
    # No arguments.
    []

#### Output

    # Return::Set compatible specification

    # A list (possibly empty) of hashrefs, one per domain:
    (
        {
            type => HASHREF,
            keys => {
                # Always present:
                domain => { type => SCALAR },
                source => { type => SCALAR },

                # Optional -- absent when information is unavailable:
                web_ip    => { type => SCALAR, optional => 1,
                               regex => qr/^\d{1,3}(?:\.\d{1,3}){3}$/ },
                web_org   => { type => SCALAR, optional => 1 },
                web_abuse => { type => SCALAR, optional => 1 },

                mx_host  => { type => SCALAR, optional => 1 },
                mx_ip    => { type => SCALAR, optional => 1,
                              regex => qr/^\d{1,3}(?:\.\d{1,3}){3}$/ },
                mx_org   => { type => SCALAR, optional => 1 },
                mx_abuse => { type => SCALAR, optional => 1 },

                ns_host  => { type => SCALAR, optional => 1 },
                ns_ip    => { type => SCALAR, optional => 1,
                              regex => qr/^\d{1,3}(?:\.\d{1,3}){3}$/ },
                ns_org   => { type => SCALAR, optional => 1 },
                ns_abuse => { type => SCALAR, optional => 1 },

                registrar       => { type => SCALAR, optional => 1 },
                registrar_abuse => { type => SCALAR, optional => 1 },

                registered => { type => SCALAR, optional => 1,
                                regex => qr/^\d{4}-\d{2}-\d{2}$/ },
                expires    => { type => SCALAR, optional => 1,
                                regex => qr/^\d{4}-\d{2}-\d{2}$/ },

                recently_registered => { type => SCALAR, optional => 1,
                                         regex => qr/^1$/ },

                whois_raw => { type => SCALAR, optional => 1 },
            },
        },
        # ... one hashref per unique domain, in first-seen order
    )

    # Empty list when no qualifying domains are found.

## all\_domains()

### Purpose

Returns the union of every registrable domain seen anywhere in the message:
URL hosts from `embedded_urls()` and contact domains from
`mailto_domains()`, collapsed to their registrable eTLD+1 form and
deduplicated.

This is the high-level answer to "what domains does this message reference?"
It is suitable for bulk lookups, domain reputation checks, or feeds into
external threat-intelligence systems where you want a flat, deduplicated
list rather than the detailed per-domain hashrefs returned by the individual
methods.

Unlike `mailto_domains()`, this method triggers no additional network I/O
beyond what `embedded_urls()` and `mailto_domains()` already perform; it
is a pure in-memory union and normalisation of their results.

### Usage

    $analyser->parse_email($raw);
    my @domains = $analyser->all_domains();

    # Print every unique registrable domain
    print "$_\n" for @domains;

    # Feed into a reputation lookup
    for my $dom (@domains) {
        my $score = $reputation_api->lookup($dom);
        warn "Known bad domain: $dom\n" if $score > 0.8;
    }

    # Check for overlap with a known-bad domain list
    my %blocklist = map { $_ => 1 } @known_bad_domains;
    my @hits = grep { $blocklist{$_} } @domains;

### Arguments

None.  `parse_email()` must have been called first.  Calling
`all_domains()` before `embedded_urls()` or `mailto_domains()` is safe;
it will trigger both lazily.

### Returns

A list (not an arrayref) of plain strings, each being a registrable
eTLD+1 domain name (see Algorithm below), lower-cased, with no duplicates,
in first-seen order.  Returns an empty list if the message contains no
URLs and no contact domains, or if `parse_email()` has not been called.

The list contains plain scalars, not hashrefs.  For the full intelligence
detail associated with each domain, call `embedded_urls()` and
`mailto_domains()` directly.

### Side Effects

Triggers `embedded_urls()` and `mailto_domains()` if they have not
already been called on the current message, which in turn performs network
I/O as documented in those methods.  No additional network I/O is performed
beyond what those two methods require.  Results are not independently cached;
the caching is handled by `embedded_urls()` and `mailto_domains()`.

### Algorithm: eTLD+1 normalisation

Both input sources are normalised to their registrable domain
(eTLD+1) before deduplication, using the following heuristic:

- A hostname with no dot (e.g. `localhost`) is discarded (returns `undef`
from the internal function and is skipped).
- A hostname with exactly two labels (e.g. `example.com`, `evil.ru`) is
returned as-is; it is already registrable.
- A hostname with three or more labels is inspected at the TLD (last label)
and the second-level (penultimate label).  If the TLD is a two-letter
country code (`uk`, `au`, `jp`, etc.) and the second-level label is one
of the common delegated second-levels `co`, `com`, `net`, `org`,
`gov`, `edu`, `ac`, or `me`, then three labels are kept (e.g.
`mail.evil.co.uk` becomes `evil.co.uk`).  Otherwise two labels are kept
(e.g. `mail.evil.com` becomes `evil.com`).

This heuristic handles the most common cases correctly.  It is not a full
Public Suffix List implementation; uncommon second-level delegations (e.g.
`.ltd.uk`, `.plc.uk`, `.asn.au`) are not recognised and will produce
a two-label result that includes the second-level label rather than three
labels.

The normalisation is applied to both sources:

- URL hosts (from `embedded_urls()`): the host extracted from each
URL is normalised.  For example, the URL
`https://www.spamco.example/offer` contributes `spamco.example`.
- Contact domains (from `mailto_domains()`): the full domain
stored in each hashref is normalised.  For example, the From: address
`<spammer@sub.spamco.example>` contributes `spamco.example`.

This means a URL at `www.spamco.example` and a contact address at
`sub.spamco.example` both collapse to `spamco.example`, and that domain
appears only once in the result.

### Notes

- Domains from `mailto_domains()` are normalised before deduplication;
domains from `embedded_urls()` are also normalised.  This differs from
`mailto_domains()` itself, which stores the full subdomain (e.g.
`sub.spamco.example`) in its `domain` key.  The loss of subdomain
granularity is intentional: `all_domains()` is designed for registrar-
and ISP-level lookups, where the registrable domain is the relevant unit.
- The returned strings are lower-cased.  No trailing dot is ever present.
- The order of elements is: URL-host domains first (in the order URLs were
first seen), followed by contact domains (in the order they were first
collected by `mailto_domains()`), with any domain already seen from the
URL pass omitted from the contact-domain pass.
- A domain that appears only as a subdomain in one source and only as a
registrable domain in another source will still be deduplicated correctly,
because both are normalised to the same registrable form before the
deduplication check.
- Calling `all_domains()` does not interfere with or invalidate the caches
of `embedded_urls()` or `mailto_domains()`; those methods can still be
called afterwards to retrieve their full detail.

### API Specification

#### Input

    # Params::Validate::Strict compatible specification
    # No arguments.
    []

#### Output

    # Return::Set compatible specification

    # A list (possibly empty) of plain strings:
    (
        {
            type  => SCALAR,
            regex => qr/^[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?$/,
            # Lower-cased registrable domain; no trailing dot;
            # at least two dot-separated labels.
        },
        # ... one string per unique registrable domain, in first-seen order
    )

    # Empty list when the message contains no URLs and no contact domains.

## sending\_software()

### Purpose

Returns information extracted from headers that identify the software or
server-side infrastructure used to compose or inject the message.  These
headers are injected by email clients, bulk-mailing libraries, and shared
hosting control panels, and are often the most direct evidence of how the
spam was sent and from which server.

Headers examined: `X-Mailer`, `User-Agent`, `X-PHP-Originating-Script`,
`X-Source`, `X-Source-Args`, `X-Source-Host`.

The `X-PHP-Originating-Script`, `X-Source`, and `X-Source-Host` headers
in particular are injected automatically by many shared hosting providers
(cPanel, Plesk, DirectAdmin) and reveal the exact PHP script path and
hostname responsible.  A hosting abuse team can use these values to
identify the compromised or malicious account immediately, without needing
to search logs.

The data is extracted synchronously during `parse_email()` with no network
I/O.  This method simply returns the pre-built list.

### Usage

    $analyser->parse_email($raw);
    my @sw = $analyser->sending_software();

    for my $s (@sw) {
        printf "%-30s : %s\n", $s->{header}, $s->{value};
        printf "  Note: %s\n", $s->{note};
    }

    # Check for shared-hosting injection headers
    my @hosting = grep {
        $_->{header} =~ /^x-(?:php-originating-script|source)/
    } @sw;

    if (@hosting) {
        print "Shared-hosting script detected -- report to hosting abuse team:\n";
        print "  $_->{header}: $_->{value}\n" for @hosting;
    }

    # Extract the mailer name if present
    my ($mailer) = grep { $_->{header} eq 'x-mailer' } @sw;
    printf "Sent with: %s\n", $mailer->{value} if $mailer;

### Arguments

None.  `parse_email()` must have been called first.

### Returns

A list (not an arrayref) of hashrefs, one per recognised software-fingerprint
header that was present in the message, in alphabetical order of header name.
Returns an empty list if none of the watched headers are present, or if
`parse_email()` has not been called.

    {
        header => 'X-PHP-Originating-Script',
        value  => '1000:newsletter.php',
        note   => 'PHP script on shared hosting - report to hosting abuse team',
    }

Each hashref contains exactly three keys, all always present:

- `header` (string)

    The header name, lower-cased.  One of the six values listed in the
    Algorithm section below.

- `value` (string)

    The header value exactly as it appeared in the message (not decoded or
    transformed in any way).

- `note` (string)

    A fixed, human-readable annotation describing what this header represents
    and the recommended action.  The note string is determined by the header
    name and is the same for all messages; it is not derived from the value.
    See the Algorithm section for the note associated with each header.

### Side Effects

None.  All data is collected during `parse_email()` and this method
only returns the pre-collected list.  No network I/O is performed.

### Algorithm: headers examined

The following six headers are examined during `parse_email()`.  They are
checked in alphabetical order; the result list preserves that order
(i.e. `user-agent` appears before `x-mailer` which appears before
`x-php-originating-script`, etc.).  At most one entry per header name is
produced even if the header appears more than once; the first occurrence is
used.

- `user-agent`

    Note: `"Email client identifier"`

    Set by some email clients (Thunderbird, Evolution) as an alternative to
    `X-Mailer`.  Identifies the application that composed the message.

- `x-mailer`

    Note: `"Email client or bulk-mailer identifier"`

    The most widely used header for identifying the sending application.
    Values range from standard clients (`"Apple Mail"`, `"Microsoft Outlook"`)
    to bulk-mailing libraries (`"PHPMailer 6.0"`, `"MailMate"`).  Its presence
    in spam often reveals the library used to generate the campaign.

- `x-php-originating-script`

    Note: `"PHP script on shared hosting -- report to hosting abuse team"`

    Injected by cPanel and similar shared-hosting control panels when a PHP
    script sends mail via the local MTA.  The value typically takes the form
    `uid:script.php` (e.g. `"1000:newsletter.php"`), directly identifying
    the Unix user account and the script responsible.  This is the single most
    actionable header for shared-hosting abuse reports.

- `x-source`

    Note: `"Source file on shared hosting -- report to hosting abuse team"`

    Also injected by shared-hosting platforms, typically containing the full
    filesystem path to the sending script (e.g.
    `"/home/user/public_html/contact.php"`).  Complements
    `X-PHP-Originating-Script`.

- `x-source-args`

    Note: `"Command-line args injected by shared hosting provider"`

    The command-line arguments of the process that sent the mail, injected by
    some hosting platforms.  May reveal interpreter invocations or script
    parameters useful for forensic analysis.

- `x-source-host`

    Note: `"Sending hostname injected by shared hosting provider"`

    The hostname of the server that submitted the message, injected by the
    hosting platform.  Useful when the IP in the `Received:` chain is a shared
    outbound relay rather than the originating server.

### Notes

- The result list is reset to empty by each call to `parse_email()`.  If no
watched headers are present in the current message, the list is empty.
- The alphabetical ordering of entries is a side effect of iterating over
the `%sw_notes` hash in sorted key order.  It is stable across calls on
the same message.
- Header names are stored lower-cased (e.g. `'x-mailer'`, not `'X-Mailer'`).
Header values are stored verbatim, preserving the original case and
whitespace.
- The `note` field is a fixed annotation string chosen by the module, not
text extracted from the message.  It is safe to display directly in reports
without sanitisation.
- If both `X-PHP-Originating-Script` and `X-Source` are present (common on
cPanel systems), both are returned as separate list entries.  A caller
building a hosting abuse report should include all entries whose `header`
begins with `x-`.

### API Specification

#### Input

    # Params::Validate::Strict compatible specification
    # No arguments.
    []

#### Output

    # Return::Set compatible specification

    # A list (possibly empty) of hashrefs, in alphabetical header-name order:
    (
        {
            type => HASHREF,
            keys => {
                header => {
                    type  => SCALAR,
                    regex => qr/^(?:user-agent|x-mailer|x-php-originating-script
                                   |x-source|x-source-args|x-source-host)$/x,
                },
                value => {
                    type => SCALAR,
                    # Verbatim header value; may be any non-empty string.
                },
                note => {
                    type  => SCALAR,
                    # Fixed annotation string; one of the six strings
                    # documented in the Algorithm section above.
                },
            },
        },
        # ... one hashref per recognised header present, alphabetical order
    )

    # Empty list when none of the six watched headers are present.

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
              detail => 'bit.ly used - real destination hidden' },
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

    Sending ISP            - network owner of the originating IP
    URL host               - network owner of each unique web-server IP
    Mail host (MX)         - network owner of the domain's MX record IP
    DNS host (NS)          - network owner of the authoritative NS IP
    Domain registrar       - registrar abuse contact from domain WHOIS
    Account provider       - e.g. Gmail / Outlook for the From:/Sender: account
    DKIM signer            - the organisation whose key signed the message
    ESP / bulk sender      - identified via List-Unsubscribe: domain

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
