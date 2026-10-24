Email Header Decoder, plan

Four steps. Each ends with a report and a commit, and the next prompt
is handed out only after that. Status as of 2026-10-24.

1  Repo, parser, hop timeline, page skeleton, tests, build.    DONE
   parse.js (header block in a bare paste, a full .eml, a Show
   original copy, or Outlook's box; unfolding and lost indentation
   repair; RFC 2047; addresses; RFC 5322 dates), psl.js, received.js
   (hop chain, delays, slowest hop, clock skew, internal groups, TLS
   evidence, trust line, stated origin), analyze.js, the page with
   Message, Path and Headers cards, build.js with a CSP that has no
   connect-src. Commits fdc8708 and 20038f4, then a66383d, the
   step 1 gap fill against Cowork prompt 1.

2  Authentication-Results, ARC, alignment table, computed DMARC. DONE
   auth.js: RFC 8601 per method with the host that wrote each field
   and whether the Received chain backs it; ARC sets per RFC 8617
   with chain checks; alignment per identifier in relaxed and strict
   mode; a DMARC result computed here beside the reported one, and a
   named reason when they disagree. Commits a8113ed and 49de0d9,
   then the Step 2 check commit against the 2026-10-23 spec: primary
   and untrusted Authentication-Results, Received-SPF as SPF source,
   DKIM matching by s= or b=, HELO identity for a null reverse path,
   computed DMARC as pass, fail or none, two From fields.

3  Finding sentence and provider decode.                    DONE
   finding.js (status pass, fail, forwarded, none, error or unknown;
   headline, cause, policy consequence, details, fixes, flags, and
   limits; forwarded mail from the ARC chain with the pre-forward
   results quoted) and providers.js (Microsoft, Google, Proofpoint,
   Mimecast, Cisco, Barracuda, SpamAssassin, Rspamd; platform with
   a confidence; list and sending headers with RFC 8058), both in
   the build. The product name is Email Header Decoder and the repo
   is email-header-decoder (renamed 24 Oct). wip/step3 and the
   15 Oct verdict.js are gone.

4  Copy pass, mobile, hosting.                              NOT STARTED
   Hosting is a static site, likely headers.dns-audit.com on
   Cloudflare with a link in the dns-audit.com nav. The droplet never
   serves it.
