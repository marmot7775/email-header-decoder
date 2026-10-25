# Email Header Decoder (beta)

Paste the headers of any email and read, in one sentence, why it
passed or failed SPF, DKIM, and DMARC, and what to fix.

Live at https://headers.dns-audit.com, part of
[dns-audit.com](https://dns-audit.com).

![Email Header Decoder](ui/og-card.png)

## What it does that a header table does not

- **The finding first.** One sentence naming the cause, in plain
  words with the technical line under it, then the fix as steps.
- **Two DMARC results.** The receiver's, and one worked out on the
  page from the identifiers, with the reason when they disagree.
- **Forwards read correctly.** The ARC chain shows what passed
  before a forward, so a message the sender set up correctly is not
  blamed on the sender.
- **Trust, not just parsing.** Authentication-Results fields a
  sender could have written are shown but never used. The hop
  timeline marks where the receiver took custody.
- **Filter headers decoded** for Microsoft 365, Google, Proofpoint,
  Mimecast, Cisco, Barracuda, SpamAssassin, and Rspamd, with the raw
  value beside each one.
- **Every sentence points at its source.** Select a line reference
  and the raw header lines it came from light up.
- **It says what headers cannot show** instead of guessing.
- **Copy report** gives a plain text summary for a ticket or a
  client email.

## Privacy

Everything runs in your browser. There is no server, no analytics,
and no storage, and the page makes no network requests. Its
Content Security Policy has no `connect-src`, so the browser blocks
any attempt to send data out. You can save the page and use it with
the network off.

## Limits

No DNS lookups and no signature verification: the page reads the
results the receiving server recorded at delivery. The
organizational domain comes from a short built-in suffix list.
ARC seals are checked for structure, not verified.

Not yet: DKIM key lookup, bounce and SMTP code decoding, comparing
two messages. Shareable result links are left out on purpose; they
would need a server.

## Beta

So far it is tested against synthetic headers built from the RFCs
and vendor documentation, so it will get some real messages wrong. If it reads one wrong, email dns@dns-audit.com with what it
said and what it should have said, or open an issue. Please
describe the problem rather than attaching someone else's headers.

## Run it

Node 18 or later, no dependencies.

    node --test test/      run the tests
    node build.js          build dist/

`dist/index.html` is the whole tool in one file and opens from
disk. The fixtures in `test/fixtures` are synthetic; no real mail is
committed.

## Author

Built by [Neil Anuskiewicz](https://dns-audit.com/about), email
deliverability and DNS consultant.

## License

MIT
