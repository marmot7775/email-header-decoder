Email Header Decoder, plan

Four steps. Each ends with a report and a commit, and the next prompt
is handed out only after that. Status as of 2026-10-25.

1  Repo, parser, hop timeline, page skeleton, tests, build.    DONE
   parse.js (header block in a bare paste, a full .eml, a Show
   original copy, or Outlook's box; unfolding and lost indentation
   repair; RFC 2047; addresses; RFC 5322 dates), psl.js, received.js
   (hop chain, delays, slowest hop, clock skew, internal groups, TLS
   evidence, trust line, stated origin), analyze.js, the page with
   Message, Path and Headers cards, build.js with a CSP that has no
   connect-src. Commits f54c7bc and 30058f5, then 3535036, the
   step 1 gap fill against Cowork prompt 1.

2  Authentication-Results, ARC, alignment table, computed DMARC. DONE
   auth.js: RFC 8601 per method with the host that wrote each field
   and whether the Received chain backs it; ARC sets per RFC 8617
   with chain checks; alignment per identifier in relaxed and strict
   mode; a DMARC result computed here beside the reported one, and a
   named reason when they disagree. Commits 594feac and 8cf9fa1,
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

4  Copy pass, design, mobile, hosting.                      IN PROGRESS
   Design pass done 2026-10-25: dns-audit.com site bar and footer,
   Beta label, check tiles, plain first with the technical line
   under it, numbered fixes, evidence folded, quieter line chips,
   filter headers after the path, Copy report, samples labelled,
   static guide and FAQ, head with JSON-LD, share card, host files.
   Published 2026-10-25: public repo marmot7775/email-header-decoder,
   live at headers.dns-audit.com (Workers static assets from dist/,
   wrangler.jsonc, workers.dev off). Still to do: real headers from
   Neil, the copy pass they drive, and the dns-audit.com nav link.

Decisions

2026-10-15  Runs entirely in the browser. No server, no network
            calls, no DNS, no signature verification.
2026-10-23  Step 2 check rules, as listed in CLAUDE.md under
            Settled by the step 2 check.
2026-10-24  Renamed Header Verdict to Email Header Decoder; the one
            sentence result is the finding.
2026-10-25  Hosted at headers.dns-audit.com as a static site on
            Cloudflare, styled as part of the dns-audit.com family.
            A subdomain, not a path, for simplicity; neither harms
            search.
2026-10-25  Public repo with a Beta label; version stays under 1.0.
2026-10-25  Plain wording first. The plain headline leads and the
            technical one sits under it; the switch changes the rest.
            The voice choice is no longer kept in localStorage, so
            the no storage rule holds.
2026-10-25  Links to dns-audit.com, Neil's LinkedIn, and the GitHub
            repo are allowed on the page. A link sends nothing until
            followed; the CSP still blocks every request the page
            itself could make. The build refuses any other host.
2026-10-25  Static guide and FAQ under the tool, for readers and for
            search and AI crawlers. The JSON-LD FAQ is generated
            from the page's FAQ so the two match; a test checks it.
2026-10-25  The page opens on the forwarded sample, labelled as a
            sample.
2026-10-25  Check tiles and Copy report read values already in the
            result. When the finding blames a forward, the tiles say
            failed after the forward and passed before it, from the
            first ARC set.
