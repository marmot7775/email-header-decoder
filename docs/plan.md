Header Verdict, plan

Four steps. Each ends with a report and a commit, and the next prompt
is handed out only after that. Status as of 2026-10-23.

1  Repo, parser, hop timeline, page skeleton, tests, build.    DONE
   parse.js (header block in a bare paste, a full .eml, a Show
   original copy, or Outlook's box; unfolding and lost indentation
   repair; RFC 2047; addresses; RFC 5322 dates), psl.js, received.js
   (hop chain, delays, slowest hop, clock skew, internal groups, TLS
   evidence, trust line, stated origin), analyze.js, the page with
   Message, Path and Headers cards, build.js with a CSP that has no
   connect-src. Commits fdc8708 and 20038f4, then the step 1 gap
   fill against Cowork prompt 1.

2  Authentication-Results, ARC, alignment table, computed DMARC. DONE
   auth.js: RFC 8601 per method with the host that wrote each field
   and whether the Received chain backs it; ARC sets per RFC 8617
   with chain checks; alignment per identifier in relaxed and strict
   mode; a DMARC result computed here beside the reported one, and a
   named reason when they disagree. Commits a8113ed and 49de0d9.

3  Verdict sentence and provider decode.                    NOT STARTED
   verdict.js and providers.js hold the 15 Oct prototype and are not
   in the build. A first rewrite of providers.js against Microsoft's
   published tables is parked outside the repo at
   C:\Users\nta37\Scripts\scratch\header-verdict-step3-wip.

4  Copy pass, mobile, hosting.                              NOT STARTED
   Hosting is a static site, likely headers.dns-audit.com on
   Cloudflare with a link in the dns-audit.com nav. The droplet never
   serves it.
