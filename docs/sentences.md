# Sentence inventory

## pass by DKIM

Plain headline: This message passed the sender check (DMARC). It was signed by shop.example, the domain in the From address.

Technical headline: DMARC at mx.receiver.example passed because DKIM d=shop.example s=s1 passed, and it aligns with the From domain shop.example (RFC5322.From).

Cause, plain: A message passes when it's signed by, or sent for, the domain in its From address, and this one was.

Cause, technical: For shop.example, the pass comes from aligned DKIM, which still passes after a forward if nothing alters the signed headers or body.

Policy, plain: The message passed, so the sender's DMARC setting didn't come into play.

Policy, technical: shop.example publishes p=reject, which asks for failing mail to be refused. This message passed, so the policy did not come into play.

Delivery, plain: Mail sent this way meets the rules Gmail, Yahoo, and Microsoft's Outlook.com set for proving who sent a message. Those rules also cover spam complaints and unsubscribe links, which the headers don't show.

Delivery, technical: SPF and DKIM both pass, and one aligns with the From domain shop.example, which publishes a DMARC record. That meets the authentication requirements for bulk senders. Google's Email sender guidelines, Yahoo's Sender Best Practices, and Microsoft's Outlook.com requirements for high volume senders all say so. Their spam rate and unsubscribe requirements are outside the headers.

Detail 1, plain: The message was signed by shop.example, which belongs to the sender.

Detail 1, technical: DKIM passed for d=shop.example s=s1, which aligns with shop.example.

Detail 2, plain: The sending server is approved, but by bounce.mailer.example, not by the sender's own domain.

Detail 2, technical: SPF passed for bounce.mailer.example, which does not align with shop.example. A pass on another domain does not count for DMARC.

Fix 1, plain: Nothing needs fixing. If you want both checks to match, give the service that sends this mail a custom return address on shop.example (often called a custom return path).

Fix 1, technical: Alignment comes from DKIM alone, which is enough. For SPF to align too, set a custom Return-Path domain under shop.example at the sending service.

Limit 1, plain: This page assumes the usual, looser domain match. A domain's DMARC setting can demand an exact match, and the headers don't show that setting.

Limit 1, technical: Alignment is computed in relaxed mode, the DMARC default, with strict mode beside it. adkim and aspf are set in the DMARC record, which is not in the headers.

Sender signals, plain: Yes, as far as the headers show.

Sender signals, technical: No flag fired: DMARC passed for shop.example, and the display name, Reply-To, and From domain raise nothing.

Spam signals, plain: These headers can't say. They carry no spam rating from the receiving system that this page can read.

Spam signals, technical: No spam filter result that this page can read was written by the receiver.

Signals, nothing fired, plain: Nothing in the headers points to forgery or spam. That covers the headers only, because this page doesn't judge the message text, links, or attachments.

Signals, nothing fired, technical: Nothing in the headers points to forgery or spam. That is a statement about the headers only: the body, links and attachments are not examined.

## pass by SPF

Plain headline: This message passed the sender check (DMARC). It came from a server allowed by shop.example, the domain in the From address.

Technical headline: DMARC at mx.receiver.example passed because SPF passed for the Return-Path domain shop.example (RFC5321.MailFrom), and it aligns with the From domain shop.example (RFC5322.From).

Cause, plain: A message passes when it's signed by, or sent for, the domain in its From address, and this one was.

Cause, technical: For shop.example, only SPF passes and aligns. A forward or a mailing list breaks it, because SPF checks whichever server hands the message over; aligned DKIM would still pass.

Policy, plain: The message passed, so the sender's DMARC setting didn't come into play.

Policy, technical: shop.example publishes p=reject, which asks for failing mail to be refused. This message passed, so the policy did not come into play.

Delivery, plain: Mail sent this way meets the basic rule at Gmail and Yahoo, but not the rule for bulk senders. Anyone sending in bulk must also add a digital signature (DKIM). Gmail and Outlook.com count bulk as 5,000 messages a day, and may refuse mail that falls short or send it to spam.

Delivery, technical: Only SPF passes here. That meets the requirement for all senders, SPF or DKIM, but bulk senders need both to pass. Google's Email sender guidelines, Yahoo's Sender Best Practices, and Microsoft's Outlook.com requirements for high volume senders all say so. Google and Microsoft draw the line at 5,000 messages a day, and mail that falls short may be rejected or marked as spam.

Detail 1, plain: The sending server is approved by shop.example, which belongs to the sender.

Detail 1, technical: SPF passed for shop.example, which aligns with shop.example.

Fix 1, plain: Turn on email signing (DKIM) for shop.example in the settings of the service that sends this mail. It adds a digital signature with your domain to every message, and that signature still works when mail is forwarded.

Fix 1, technical: DMARC depends on SPF alone, and a forward breaks SPF. Turn on DKIM signing for shop.example at the sending service. Aligned DKIM lets DMARC pass, including after a forward.

Limit 1, plain: This page assumes the usual, looser domain match. A domain's DMARC setting can demand an exact match, and the headers don't show that setting.

Limit 1, technical: Alignment is computed in relaxed mode, the DMARC default, with strict mode beside it. adkim and aspf are set in the DMARC record, which is not in the headers.

Sender signals, plain: Yes, as far as the headers show.

Sender signals, technical: No flag fired: DMARC passed for shop.example, and the display name, Reply-To, and From domain raise nothing.

Spam signals, plain: These headers can't say. They carry no spam rating from the receiving system that this page can read.

Spam signals, technical: No spam filter result that this page can read was written by the receiver.

Signals, nothing fired, plain: Nothing in the headers points to forgery or spam. That covers the headers only, because this page doesn't judge the message text, links, or attachments.

Signals, nothing fired, technical: Nothing in the headers points to forgery or spam. That is a statement about the headers only: the body, links and attachments are not examined.

## pass by both

Plain headline: This message passed the sender check (DMARC). It was signed by shop.example, the domain in the From address, and came from a server it allows.

Technical headline: DMARC at mx.receiver.example passed because DKIM d=shop.example s=s1 passed and SPF passed for the Return-Path domain shop.example (RFC5321.MailFrom), and both align with the From domain shop.example (RFC5322.From).

Cause, plain: A message passes when it's signed by, or sent for, the domain in its From address, and this one was.

Cause, technical: For shop.example, both SPF and DKIM pass and align, so the message still passes after a forward that breaks SPF.

Policy, plain: The message passed, so the sender's DMARC setting didn't come into play.

Policy, technical: shop.example publishes p=none, which asks for no action. This message passed, so the policy did not come into play.

Delivery, plain: Mail sent this way meets the rules Gmail, Yahoo, and Microsoft's Outlook.com set for proving who sent a message. Those rules also cover spam complaints and unsubscribe links, which the headers don't show.

Delivery, technical: SPF and DKIM both pass, and both align with the From domain shop.example, which publishes a DMARC record. That meets the authentication requirements for bulk senders. Google's Email sender guidelines, Yahoo's Sender Best Practices, and Microsoft's Outlook.com requirements for high volume senders all say so. Their spam rate and unsubscribe requirements are outside the headers.

Detail 1, plain: The message was signed by shop.example, which belongs to the sender.

Detail 1, technical: DKIM passed for d=shop.example s=s1, which aligns with shop.example.

Detail 2, plain: The sending server is approved by shop.example, which belongs to the sender.

Detail 2, technical: SPF passed for shop.example, which aligns with shop.example.

Fix 1, plain: Your DMARC setting only watches. It doesn't stop fake mail that uses your domain. Once the DMARC reports show all your real mail passing, ask whoever manages the DNS for shop.example to change it to quarantine.

Fix 1, technical: shop.example publishes p=none, so forged mail is not stopped. Once aggregate reports show every real source passing, move to p=quarantine.

Limit 1, plain: This page assumes the usual, looser domain match. A domain's DMARC setting can demand an exact match, and the headers don't show that setting.

Limit 1, technical: Alignment is computed in relaxed mode, the DMARC default, with strict mode beside it. adkim and aspf are set in the DMARC record, which is not in the headers.

Sender signals, plain: Yes, as far as the headers show.

Sender signals, technical: No flag fired: DMARC passed for shop.example, and the display name, Reply-To, and From domain raise nothing.

Spam signals, plain: These headers can't say. They carry no spam rating from the receiving system that this page can read.

Spam signals, technical: No spam filter result that this page can read was written by the receiver.

Signals, nothing fired, plain: Nothing in the headers points to forgery or spam. That covers the headers only, because this page doesn't judge the message text, links, or attachments.

Signals, nothing fired, technical: Nothing in the headers points to forgery or spam. That is a statement about the headers only: the body, links and attachments are not examined.

## pass reported with nothing aligned

Plain headline: This message passed the sender check (DMARC), but its own checks don't match shop.example. The receiving system passed it for a reason the headers don't show.

Technical headline: DMARC passed at mx.receiver.example for a reason these headers do not show; in these headers there was no DKIM signature and SPF passed for the Return-Path domain bounce.mailer.example (RFC5321.MailFrom), and nothing aligned with the From domain shop.example.

Cause, plain: The checks don't line up, but the receiving system passed the message anyway, probably because of its own rules.

Cause, technical: No reported pass aligns with shop.example, yet the receiver reported dmarc=pass. A local policy, or a result it did not write into these headers, is the likely reason.

Policy, plain: The message passed, so the sender's DMARC setting didn't come into play.

Policy, technical: shop.example publishes p=reject, which asks for failing mail to be refused. This message passed, so the policy did not come into play.

Delivery: none written

Detail 1, plain: The sending server is approved, but by bounce.mailer.example, not by the sender's own domain.

Detail 1, technical: SPF passed for bounce.mailer.example, which does not align with shop.example. A pass on another domain does not count for DMARC.

Fix 1, plain: Turn on email signing (DKIM) for shop.example in the settings of the service that sends this mail. It adds a digital signature with your domain to every message, and that signature still works when mail is forwarded.

Fix 1, technical: DMARC depends on SPF alone, and a forward breaks SPF. Turn on DKIM signing for shop.example at the sending service. Aligned DKIM lets DMARC pass, including after a forward.

Limit 1, plain: This page assumes the usual, looser domain match. A domain's DMARC setting can demand an exact match, and the headers don't show that setting.

Limit 1, technical: Alignment is computed in relaxed mode, the DMARC default, with strict mode beside it. adkim and aspf are set in the DMARC record, which is not in the headers.

Sender signals, plain: Yes, as far as the headers show.

Sender signals, technical: No flag fired: DMARC passed for shop.example, and the display name, Reply-To, and From domain raise nothing.

Spam signals, plain: These headers can't say. They carry no spam rating from the receiving system that this page can read.

Spam signals, technical: No spam filter result that this page can read was written by the receiver.

Signals, nothing fired, plain: Nothing in the headers points to forgery or spam. That covers the headers only, because this page doesn't judge the message text, links, or attachments.

Signals, nothing fired, technical: Nothing in the headers points to forgery or spam. That is a statement about the headers only: the body, links and attachments are not examined.

## pass computed, no DMARC result reported

Plain headline: The receiving system didn't record the sender check, so this page worked it out. This message passed the sender check (DMARC). It was signed by shop.example, the domain in the From address.

Technical headline: mx.receiver.example recorded no DMARC result; worked out from the identifiers, DMARC passes because DKIM d=shop.example s=s1 passed, and it aligns with the From domain shop.example (RFC5322.From).

Cause, plain: A message passes when it's signed by, or sent for, the domain in its From address, and this one was.

Cause, technical: For shop.example, the pass comes from aligned DKIM, which still passes after a forward if nothing alters the signed headers or body. Worked out here; the receiver recorded no DMARC result.

Policy, plain: The headers don't say what shop.example asks mail providers to do with fake mail.

Policy, technical: mx.receiver.example did not quote the DMARC policy of shop.example, so the headers do not show what a failure means for this domain. The record is in DNS, which this page does not read.

Delivery, plain: Mail sent this way meets the rules Gmail, Yahoo, and Microsoft's Outlook.com set for proving who sent a message. They also require a DMARC setting, which these headers don't show. Those rules also cover spam complaints and unsubscribe links, which the headers don't show.

Delivery, technical: SPF and DKIM both pass, and one aligns with the From domain shop.example. That meets the authentication requirements for bulk senders. Google's Email sender guidelines, Yahoo's Sender Best Practices, and Microsoft's Outlook.com requirements for high volume senders all say so. They also require a DMARC record, which these headers do not show. Their spam rate and unsubscribe requirements are outside the headers.

Detail 1, plain: The message was signed by shop.example, which belongs to the sender.

Detail 1, technical: DKIM passed for d=shop.example s=s1, which aligns with shop.example.

Detail 2, plain: The sending server is approved, but by bounce.mailer.example, not by the sender's own domain.

Detail 2, technical: SPF passed for bounce.mailer.example, which does not align with shop.example. A pass on another domain does not count for DMARC.

Fix 1, plain: Nothing needs fixing. If you want both checks to match, give the service that sends this mail a custom return address on shop.example (often called a custom return path).

Fix 1, technical: Alignment comes from DKIM alone, which is enough. For SPF to align too, set a custom Return-Path domain under shop.example at the sending service.

Limit 1, plain: This page assumes the usual, looser domain match. A domain's DMARC setting can demand an exact match, and the headers don't show that setting.

Limit 1, technical: Alignment is computed in relaxed mode, the DMARC default, with strict mode beside it. adkim and aspf are set in the DMARC record, which is not in the headers.

Sender signals, plain: Yes, as far as the headers show.

Sender signals, technical: No flag fired: DMARC passed for shop.example, and the display name, Reply-To, and From domain raise nothing.

Spam signals, plain: These headers can't say. They carry no spam rating from the receiving system that this page can read.

Spam signals, technical: No spam filter result that this page can read was written by the receiver.

Signals, nothing fired, plain: Nothing in the headers points to forgery or spam. That covers the headers only, because this page doesn't judge the message text, links, or attachments.

Signals, nothing fired, technical: Nothing in the headers points to forgery or spam. That is a statement about the headers only: the body, links and attachments are not examined.

## fail with no DKIM signature

Plain headline: This message failed the sender check (DMARC). It carried no signature and the sender's list of approved servers gave no clear answer. Nothing proved it came from shop.example.

Technical headline: DMARC at mx.receiver.example failed because there was no DKIM signature and SPF was neutral for the Return-Path domain shop.example (RFC5321.MailFrom), so no identifier passed for the From domain shop.example (RFC5322.From).

Cause, plain: The sender's list of approved servers (SPF) makes no statement about the server that sent this, and nothing else proves the mail came from shop.example.

Cause, technical: There is no DKIM signature, so DMARC depends on SPF alone. The SPF record of shop.example makes no statement about the server that handed the message over (neutral), so SPF did not pass.

Policy, plain: shop.example's DMARC setting asks providers to refuse fake mail. The recipient's email provider refused this message.

Policy, technical: shop.example publishes p=reject, which asks for failing mail to be refused, and mx.receiver.example refused this message (dis=REJECT).

Delivery, plain: shop.example's DMARC setting asks mail providers to refuse mail that fails this way. Expect the ones that follow it to refuse every message with this problem.

Delivery, technical: The DMARC record of shop.example carries p=reject, which asks receivers to reject mail that fails DMARC (RFC 9989 4.7). Every message that fails this way falls under it. A receiver is not required to honor the request, so some copies may still arrive.

Fix 1, plain: Turn on email signing (DKIM) for shop.example in the settings of the service that sends this mail. It adds a digital signature with your domain to every message, and that signature still works when mail is forwarded.

Fix 1, technical: Turn on DKIM signing for shop.example at the sending service. Aligned DKIM lets DMARC pass, including after a forward.

Limit 1, plain: This page assumes the usual, looser domain match. A domain's DMARC setting can demand an exact match, and the headers don't show that setting.

Limit 1, technical: Alignment is computed in relaxed mode, the DMARC default, with strict mode beside it. adkim and aspf are set in the DMARC record, which is not in the headers.

Sender signals, plain: Maybe not. Treat this message with care.

Sender signals, technical: One signal says the author may not be who the From line shows.

Sender signal 1, plain: This message failed the sender check (DMARC), so nothing proves it came from shop.example.

Sender signal 1, technical: DMARC failed for the From domain shop.example (RFC5322.From), so no aligned SPF or DKIM pass vouches for the author domain.

Spam signals, plain: These headers can't say. They carry no spam rating from the receiving system that this page can read.

Spam signals, technical: No spam filter result that this page can read was written by the receiver.

## fail with DKIM unaligned

Plain headline: This message failed the sender check (DMARC). It was signed by mailer.example and it came from a server that bounce.mailer.example allows. Neither of those is shop.example, the domain in the From address.

Technical headline: DMARC at mx.receiver.example failed because DKIM d=mailer.example s=m1 passed and SPF passed for the Return-Path domain bounce.mailer.example (RFC5321.MailFrom), but neither aligns with the From domain shop.example (RFC5322.From).

Cause, plain: The service sending this mail is using its own domain instead of shop.example, so the checks pass for the service but not for the sender.

Cause, technical: The checks passed, but for mailer.example and bounce.mailer.example, domains that are not shop.example. That is what happens when the sending service's own domain signs and bounces the mail. DMARC counts a pass only on the From domain or, in relaxed mode, its organizational domain.

Policy, plain: shop.example's DMARC setting asks providers to refuse fake mail. The recipient's email provider refused this message.

Policy, technical: shop.example publishes p=reject, which asks for failing mail to be refused, and mx.receiver.example refused this message (dis=REJECT).

Delivery, plain: shop.example's DMARC setting asks mail providers to refuse mail that fails this way. Expect the ones that follow it to refuse every message with this problem.

Delivery, technical: The DMARC record of shop.example carries p=reject, which asks receivers to reject mail that fails DMARC (RFC 9989 4.7). Every message that fails this way falls under it. A receiver is not required to honor the request, so some copies may still arrive.

Detail 1, plain: The message was signed, but by mailer.example, not by the sender's own domain.

Detail 1, technical: DKIM passed for d=mailer.example s=m1, which does not align with shop.example. A pass on another domain does not count for DMARC.

Detail 2, plain: The sending server is approved, but by bounce.mailer.example, not by the sender's own domain.

Detail 2, technical: SPF passed for bounce.mailer.example, which does not align with shop.example. A pass on another domain does not count for DMARC.

Fix 1, plain: In the settings of the service that sends this mail, turn on domain authentication for shop.example. The service gives you a few DNS records to add, and after that your mail is signed with your own domain instead of mailer.example.

Fix 1, technical: At the sending service, set up domain authentication for shop.example so the DKIM signature carries d=shop.example or a subdomain of it, instead of d=mailer.example.

Fix 2, plain: Once the signature is fixed, you can also give the service that sends this mail a custom return address on shop.example. Services call it a custom return path or sending domain. It's optional.

Fix 2, technical: Second, after DKIM: set a custom Return-Path (bounce) domain under shop.example at the sending service so SPF aligns too.

Limit 1, plain: This page assumes the usual, looser domain match. A domain's DMARC setting can demand an exact match, and the headers don't show that setting.

Limit 1, technical: Alignment is computed in relaxed mode, the DMARC default, with strict mode beside it. adkim and aspf are set in the DMARC record, which is not in the headers.

Sender signals, plain: Maybe not. Treat this message with care.

Sender signals, technical: One signal says the author may not be who the From line shows.

Sender signal 1, plain: This message failed the sender check (DMARC), so nothing proves it came from shop.example.

Sender signal 1, technical: DMARC failed for the From domain shop.example (RFC5322.From), so no aligned SPF or DKIM pass vouches for the author domain.

Spam signals, plain: These headers can't say. They carry no spam rating from the receiving system that this page can read.

Spam signals, technical: No spam filter result that this page can read was written by the receiver.

## fail with DKIM broken in transit

Plain headline: This message failed the sender check (DMARC). The signature didn't check out and it came from a server that bounce.mailer.example allows. Nothing that checked out matches shop.example, the domain in the From address.

Technical headline: DMARC at mx.receiver.example failed because DKIM d=shop.example s=s1 failed verification and SPF passed for the Return-Path domain bounce.mailer.example (RFC5321.MailFrom), and nothing that passed aligns with the From domain shop.example (RFC5322.From).

Cause, plain: The message was changed after it was signed, or the signature doesn't match the sender's published key.

Cause, technical: The DKIM signature from shop.example did not verify at mx.receiver.example (body hash did not verify): something changed the signed part of the message after signing, or the key in DNS does not match. SPF passed only for bounce.mailer.example, which is not shop.example.

Policy, plain: shop.example's DMARC setting asks providers to refuse fake mail. The recipient's email provider refused this message.

Policy, technical: shop.example publishes p=reject, which asks for failing mail to be refused, and mx.receiver.example refused this message (dis=REJECT).

Delivery, plain: shop.example's DMARC setting asks mail providers to refuse mail that fails this way. Expect the ones that follow it to refuse every message with this problem.

Delivery, technical: The DMARC record of shop.example carries p=reject, which asks receivers to reject mail that fails DMARC (RFC 9989 4.7). Every message that fails this way falls under it. A receiver is not required to honor the request, so some copies may still arrive.

Detail 1, plain: The signature from shop.example didn't check out.

Detail 1, technical: DKIM failed for d=shop.example s=s1 (body hash did not verify). Something changed the signed headers or body after signing, or the key in DNS does not match; the headers cannot show which.

Detail 2, plain: The sending server is approved, but by bounce.mailer.example, not by the sender's own domain.

Detail 2, technical: SPF passed for bounce.mailer.example, which does not align with shop.example. A pass on another domain does not count for DMARC.

Fix 1, plain: Ask whoever manages your mail whether anything adds a footer, a disclaimer, or tracking links after messages leave the service that sends this mail. That's the usual cause of a broken signature.

Fix 1, technical: The signature from d=shop.example broke between signing and mx.receiver.example. Look for anything that edits mail after the sending service signs it (a gateway, footer, disclaimer, or link rewriting), and check that the key at s1._domainkey.shop.example is the one it signs with.

Limit 1, plain: This page assumes the usual, looser domain match. A domain's DMARC setting can demand an exact match, and the headers don't show that setting.

Limit 1, technical: Alignment is computed in relaxed mode, the DMARC default, with strict mode beside it. adkim and aspf are set in the DMARC record, which is not in the headers.

Sender signals, plain: Maybe not. Treat this message with care.

Sender signals, technical: One signal says the author may not be who the From line shows.

Sender signal 1, plain: This message failed the sender check (DMARC), so nothing proves it came from shop.example.

Sender signal 1, technical: DMARC failed for the From domain shop.example (RFC5322.From), so no aligned SPF or DKIM pass vouches for the author domain.

Spam signals, plain: These headers can't say. They carry no spam rating from the receiving system that this page can read.

Spam signals, technical: No spam filter result that this page can read was written by the receiver.

## fail with SPF for the bounce domain only

Plain headline: This message failed the sender check (DMARC). It carried no signature and it came from a server that bounce.mailer.example allows. Nothing that checked out matches shop.example, the domain in the From address.

Technical headline: DMARC at mx.receiver.example failed because there was no DKIM signature and SPF passed for the Return-Path domain bounce.mailer.example (RFC5321.MailFrom), and nothing that passed aligns with the From domain shop.example (RFC5322.From).

Cause, plain: The service sending this mail is using its own domain instead of shop.example, so the checks pass for the service but not for the sender.

Cause, technical: The checks passed, but for bounce.mailer.example, a domain that is not shop.example. That is what happens when the sending service's own domain signs and bounces the mail. DMARC counts a pass only on the From domain or, in relaxed mode, its organizational domain.

Policy, plain: shop.example's DMARC setting asks providers to refuse fake mail. The recipient's email provider refused this message.

Policy, technical: shop.example publishes p=reject, which asks for failing mail to be refused, and mx.receiver.example refused this message (dis=REJECT).

Delivery, plain: shop.example's DMARC setting asks mail providers to refuse mail that fails this way. Expect the ones that follow it to refuse every message with this problem.

Delivery, technical: The DMARC record of shop.example carries p=reject, which asks receivers to reject mail that fails DMARC (RFC 9989 4.7). Every message that fails this way falls under it. A receiver is not required to honor the request, so some copies may still arrive.

Detail 1, plain: The sending server is approved, but by bounce.mailer.example, not by the sender's own domain.

Detail 1, technical: SPF passed for bounce.mailer.example, which does not align with shop.example. A pass on another domain does not count for DMARC.

Fix 1, plain: Turn on email signing (DKIM) for shop.example in the settings of the service that sends this mail. It adds a digital signature with your domain to every message, and that signature still works when mail is forwarded.

Fix 1, technical: Turn on DKIM signing for shop.example at the sending service. Aligned DKIM lets DMARC pass, including after a forward.

Fix 2, plain: Once the signature is fixed, you can also give the service that sends this mail a custom return address on shop.example. Services call it a custom return path or sending domain. It's optional.

Fix 2, technical: Second, after DKIM: set a custom Return-Path (bounce) domain under shop.example at the sending service so SPF aligns too.

Limit 1, plain: This page assumes the usual, looser domain match. A domain's DMARC setting can demand an exact match, and the headers don't show that setting.

Limit 1, technical: Alignment is computed in relaxed mode, the DMARC default, with strict mode beside it. adkim and aspf are set in the DMARC record, which is not in the headers.

Sender signals, plain: Maybe not. Treat this message with care.

Sender signals, technical: One signal says the author may not be who the From line shows.

Sender signal 1, plain: This message failed the sender check (DMARC), so nothing proves it came from shop.example.

Sender signal 1, technical: DMARC failed for the From domain shop.example (RFC5322.From), so no aligned SPF or DKIM pass vouches for the author domain.

Spam signals, plain: These headers can't say. They carry no spam rating from the receiving system that this page can read.

Spam signals, technical: No spam filter result that this page can read was written by the receiver.

## fail with SPF for HELO only

Plain headline: This message failed the sender check (DMARC). It carried no signature and the sending server called itself o1.mailer.example. Nothing that checked out matches shop.example, the domain in the From address.

Technical headline: DMARC at mx.receiver.example failed because there was no DKIM signature and SPF passed for the HELO identity o1.mailer.example, and nothing that passed aligns with the From domain shop.example (RFC5322.From).

Cause, plain: The message had no hidden return address (Return-Path), so the only check that passed was on the sending server's own name, which doesn't belong to shop.example.

Cause, technical: SPF passed only for the server name o1.mailer.example, which is not shop.example. The bounce address was empty, so SPF checked the name the sending server gave itself (HELO) instead of a sender domain, and nothing else passed for shop.example.

Policy, plain: shop.example's DMARC setting asks providers to refuse fake mail. The recipient's email provider refused this message.

Policy, technical: shop.example publishes p=reject, which asks for failing mail to be refused, and mx.receiver.example refused this message (dis=REJECT).

Delivery, plain: shop.example's DMARC setting asks mail providers to refuse mail that fails this way. Expect the ones that follow it to refuse every message with this problem.

Delivery, technical: The DMARC record of shop.example carries p=reject, which asks receivers to reject mail that fails DMARC (RFC 9989 4.7). Every message that fails this way falls under it. A receiver is not required to honor the request, so some copies may still arrive.

Detail 1, plain: The sending server is approved, but by o1.mailer.example, not by the sender's own domain.

Detail 1, technical: SPF passed for the HELO name o1.mailer.example, which does not align with shop.example. A pass on another domain does not count for DMARC.

Fix 1, plain: Turn on email signing (DKIM) for shop.example in the settings of the service that sends this mail. It adds a digital signature with your domain to every message, and that signature still works when mail is forwarded.

Fix 1, technical: Turn on DKIM signing for shop.example at the sending service. Aligned DKIM lets DMARC pass, including after a forward.

Limit 1, plain: This page assumes the usual, looser domain match. A domain's DMARC setting can demand an exact match, and the headers don't show that setting.

Limit 1, technical: Alignment is computed in relaxed mode, the DMARC default, with strict mode beside it. adkim and aspf are set in the DMARC record, which is not in the headers.

Sender signals, plain: Maybe not. Treat this message with care.

Sender signals, technical: One signal says the author may not be who the From line shows.

Sender signal 1, plain: This message failed the sender check (DMARC), so nothing proves it came from shop.example.

Sender signal 1, technical: DMARC failed for the From domain shop.example (RFC5322.From), so no aligned SPF or DKIM pass vouches for the author domain.

Spam signals, plain: These headers can't say. They carry no spam rating from the receiving system that this page can read.

Spam signals, technical: No spam filter result that this page can read was written by the receiver.

## fail with SPF fail

Plain headline: This message failed the sender check (DMARC). It carried no signature and the sending server isn't on the sender's list of approved servers. Nothing proved it came from shop.example.

Technical headline: DMARC at mx.receiver.example failed because there was no DKIM signature and SPF failed for the Return-Path domain shop.example (RFC5321.MailFrom), so no identifier passed for the From domain shop.example (RFC5322.From).

Cause, plain: The server that sent this isn't on the sender's list of approved servers (SPF).

Cause, technical: There is no DKIM signature, so DMARC depends on SPF alone. The server that handed the message over is not authorized by the SPF record of shop.example, as mx.receiver.example reported.

Policy, plain: shop.example's DMARC setting asks providers to refuse fake mail. The recipient's email provider refused this message.

Policy, technical: shop.example publishes p=reject, which asks for failing mail to be refused, and mx.receiver.example refused this message (dis=REJECT).

Delivery, plain: shop.example's DMARC setting asks mail providers to refuse mail that fails this way. Expect the ones that follow it to refuse every message with this problem.

Delivery, technical: The DMARC record of shop.example carries p=reject, which asks receivers to reject mail that fails DMARC (RFC 9989 4.7). Every message that fails this way falls under it. A receiver is not required to honor the request, so some copies may still arrive.

Fix 1, plain: Turn on email signing (DKIM) for shop.example in the settings of the service that sends this mail. It adds a digital signature with your domain to every message, and that signature still works when mail is forwarded.

Fix 1, technical: Turn on DKIM signing for shop.example at the sending service. Aligned DKIM lets DMARC pass, including after a forward.

Fix 2, plain: If you sent this, ask whoever manages the DNS for shop.example to add the service that sends this mail to its list of allowed servers (the SPF record). The service's setup page gives the exact entry. If you didn't send it, someone else used your domain and the check correctly failed it.

Fix 2, technical: If this is your mail, add the sending service to the SPF record of shop.example. If it is not, the SPF failure is correct.

Limit 1, plain: This page assumes the usual, looser domain match. A domain's DMARC setting can demand an exact match, and the headers don't show that setting.

Limit 1, technical: Alignment is computed in relaxed mode, the DMARC default, with strict mode beside it. adkim and aspf are set in the DMARC record, which is not in the headers.

Sender signals, plain: Maybe not. Treat this message with care.

Sender signals, technical: One signal says the author may not be who the From line shows.

Sender signal 1, plain: This message failed the sender check (DMARC), so nothing proves it came from shop.example.

Sender signal 1, technical: DMARC failed for the From domain shop.example (RFC5322.From), so no aligned SPF or DKIM pass vouches for the author domain.

Spam signals, plain: These headers can't say. They carry no spam rating from the receiving system that this page can read.

Spam signals, technical: No spam filter result that this page can read was written by the receiver.

## fail with SPF softfail

Plain headline: This message failed the sender check (DMARC). It carried no signature and the sending server isn't on the sender's list of approved servers. Nothing proved it came from shop.example.

Technical headline: DMARC at mx.receiver.example failed because there was no DKIM signature and SPF soft failed for the Return-Path domain shop.example (RFC5321.MailFrom), so no identifier passed for the From domain shop.example (RFC5322.From).

Cause, plain: The server that sent this isn't on the sender's list of approved servers (SPF), and the list asks receivers to treat that as suspicious rather than refuse it.

Cause, technical: There is no DKIM signature, so DMARC depends on SPF alone. The SPF record of shop.example does not authorize the server that handed the message over and asks receivers to treat it as suspicious rather than fail it outright (softfail), as mx.receiver.example reported.

Policy, plain: shop.example's DMARC setting asks providers to refuse fake mail. The recipient's email provider refused this message.

Policy, technical: shop.example publishes p=reject, which asks for failing mail to be refused, and mx.receiver.example refused this message (dis=REJECT).

Delivery, plain: shop.example's DMARC setting asks mail providers to refuse mail that fails this way. Expect the ones that follow it to refuse every message with this problem.

Delivery, technical: The DMARC record of shop.example carries p=reject, which asks receivers to reject mail that fails DMARC (RFC 9989 4.7). Every message that fails this way falls under it. A receiver is not required to honor the request, so some copies may still arrive.

Fix 1, plain: Turn on email signing (DKIM) for shop.example in the settings of the service that sends this mail. It adds a digital signature with your domain to every message, and that signature still works when mail is forwarded.

Fix 1, technical: Turn on DKIM signing for shop.example at the sending service. Aligned DKIM lets DMARC pass, including after a forward.

Fix 2, plain: If you sent this, ask whoever manages the DNS for shop.example to add the service that sends this mail to its list of allowed servers (the SPF record). The service's setup page gives the exact entry. If you didn't send it, someone else used your domain and the check correctly failed it.

Fix 2, technical: If this is your mail, add the sending service to the SPF record of shop.example. If it is not, the SPF failure is correct.

Limit 1, plain: This page assumes the usual, looser domain match. A domain's DMARC setting can demand an exact match, and the headers don't show that setting.

Limit 1, technical: Alignment is computed in relaxed mode, the DMARC default, with strict mode beside it. adkim and aspf are set in the DMARC record, which is not in the headers.

Sender signals, plain: Maybe not. Treat this message with care.

Sender signals, technical: One signal says the author may not be who the From line shows.

Sender signal 1, plain: This message failed the sender check (DMARC), so nothing proves it came from shop.example.

Sender signal 1, technical: DMARC failed for the From domain shop.example (RFC5322.From), so no aligned SPF or DKIM pass vouches for the author domain.

Spam signals, plain: These headers can't say. They carry no spam rating from the receiving system that this page can read.

Spam signals, technical: No spam filter result that this page can read was written by the receiver.

## fail with SPF none

Plain headline: This message failed the sender check (DMARC). It carried no signature and shop.example publishes no list of approved servers. Nothing proved it came from shop.example.

Technical headline: DMARC at mx.receiver.example failed because there was no DKIM signature and SPF found no record for the Return-Path domain shop.example (RFC5321.MailFrom), so no identifier passed for the From domain shop.example (RFC5322.From).

Cause, plain: The sender's domain publishes no list of approved servers, and nothing else proves the mail came from shop.example.

Cause, technical: There is no DKIM signature, so DMARC depends on SPF alone. shop.example publishes no SPF record, so SPF could not pass.

Policy, plain: shop.example's DMARC setting asks providers to refuse fake mail. The recipient's email provider refused this message.

Policy, technical: shop.example publishes p=reject, which asks for failing mail to be refused, and mx.receiver.example refused this message (dis=REJECT).

Delivery, plain: shop.example's DMARC setting asks mail providers to refuse mail that fails this way. Expect the ones that follow it to refuse every message with this problem.

Delivery, technical: The DMARC record of shop.example carries p=reject, which asks receivers to reject mail that fails DMARC (RFC 9989 4.7). Every message that fails this way falls under it. A receiver is not required to honor the request, so some copies may still arrive.

Fix 1, plain: Turn on email signing (DKIM) for shop.example in the settings of the service that sends this mail. It adds a digital signature with your domain to every message, and that signature still works when mail is forwarded.

Fix 1, technical: Turn on DKIM signing for shop.example at the sending service. Aligned DKIM lets DMARC pass, including after a forward.

Fix 2, plain: Ask whoever manages the DNS for shop.example to publish an SPF record listing the services that send your mail.

Fix 2, technical: Publish an SPF record for shop.example that lists the servers that send for it.

Limit 1, plain: This page assumes the usual, looser domain match. A domain's DMARC setting can demand an exact match, and the headers don't show that setting.

Limit 1, technical: Alignment is computed in relaxed mode, the DMARC default, with strict mode beside it. adkim and aspf are set in the DMARC record, which is not in the headers.

Sender signals, plain: Maybe not. Treat this message with care.

Sender signals, technical: One signal says the author may not be who the From line shows.

Sender signal 1, plain: This message failed the sender check (DMARC), so nothing proves it came from shop.example.

Sender signal 1, technical: DMARC failed for the From domain shop.example (RFC5322.From), so no aligned SPF or DKIM pass vouches for the author domain.

Spam signals, plain: These headers can't say. They carry no spam rating from the receiving system that this page can read.

Spam signals, technical: No spam filter result that this page can read was written by the receiver.

## fail with SPF permerror

Plain headline: This message failed the sender check (DMARC). It carried no signature and the sender's list of approved servers is set up wrong, so it couldn't be read. Nothing proved it came from shop.example.

Technical headline: DMARC at mx.receiver.example failed because there was no DKIM signature and SPF hit a permanent error in the record for the Return-Path domain shop.example (RFC5321.MailFrom), so no identifier passed for the From domain shop.example (RFC5322.From).

Cause, plain: The sender's list of approved servers (SPF) couldn't be read, and nothing else proves the mail came from shop.example.

Cause, technical: There is no DKIM signature, so DMARC depends on SPF alone. The SPF record of shop.example could not be evaluated (permerror): it has a syntax error or needs more than 10 DNS lookups.

Policy, plain: shop.example's DMARC setting asks providers to refuse fake mail. The recipient's email provider refused this message.

Policy, technical: shop.example publishes p=reject, which asks for failing mail to be refused, and mx.receiver.example refused this message (dis=REJECT).

Delivery, plain: shop.example's DMARC setting asks mail providers to refuse mail that fails this way. Expect the ones that follow it to refuse every message with this problem.

Delivery, technical: The DMARC record of shop.example carries p=reject, which asks receivers to reject mail that fails DMARC (RFC 9989 4.7). Every message that fails this way falls under it. A receiver is not required to honor the request, so some copies may still arrive.

Fix 1, plain: Turn on email signing (DKIM) for shop.example in the settings of the service that sends this mail. It adds a digital signature with your domain to every message, and that signature still works when mail is forwarded.

Fix 1, technical: Turn on DKIM signing for shop.example at the sending service. Aligned DKIM lets DMARC pass, including after a forward.

Fix 2, plain: The SPF record for shop.example is broken, often because it lists too many services. Ask whoever manages its DNS to check and simplify it.

Fix 2, technical: Repair the SPF record of shop.example: check its syntax and keep it within 10 DNS lookups.

Limit 1, plain: This page assumes the usual, looser domain match. A domain's DMARC setting can demand an exact match, and the headers don't show that setting.

Limit 1, technical: Alignment is computed in relaxed mode, the DMARC default, with strict mode beside it. adkim and aspf are set in the DMARC record, which is not in the headers.

Sender signals, plain: Maybe not. Treat this message with care.

Sender signals, technical: One signal says the author may not be who the From line shows.

Sender signal 1, plain: This message failed the sender check (DMARC), so nothing proves it came from shop.example.

Sender signal 1, technical: DMARC failed for the From domain shop.example (RFC5322.From), so no aligned SPF or DKIM pass vouches for the author domain.

Spam signals, plain: These headers can't say. They carry no spam rating from the receiving system that this page can read.

Spam signals, technical: No spam filter result that this page can read was written by the receiver.

## fail with SPF temperror

Plain headline: This message failed the sender check (DMARC). It carried no signature and the sender's list of approved servers couldn't be read this time. Nothing proved it came from shop.example.

Technical headline: DMARC at mx.receiver.example failed because there was no DKIM signature and SPF hit a temporary DNS error for the Return-Path domain shop.example (RFC5321.MailFrom), so no identifier passed for the From domain shop.example (RFC5322.From).

Cause, plain: The sender's list of approved servers (SPF) couldn't be read, and nothing else proves the mail came from shop.example.

Cause, technical: There is no DKIM signature, so DMARC depends on SPF alone. A temporary DNS error kept mx.receiver.example from evaluating the SPF record of shop.example (temperror).

Policy, plain: shop.example's DMARC setting asks providers to refuse fake mail. The recipient's email provider refused this message.

Policy, technical: shop.example publishes p=reject, which asks for failing mail to be refused, and mx.receiver.example refused this message (dis=REJECT).

Delivery: none written

Fix 1, plain: Turn on email signing (DKIM) for shop.example in the settings of the service that sends this mail. It adds a digital signature with your domain to every message, and that signature still works when mail is forwarded.

Fix 1, technical: Turn on DKIM signing for shop.example at the sending service. Aligned DKIM lets DMARC pass, including after a forward.

Limit 1, plain: This page assumes the usual, looser domain match. A domain's DMARC setting can demand an exact match, and the headers don't show that setting.

Limit 1, technical: Alignment is computed in relaxed mode, the DMARC default, with strict mode beside it. adkim and aspf are set in the DMARC record, which is not in the headers.

Sender signals, plain: Maybe not. Treat this message with care.

Sender signals, technical: One signal says the author may not be who the From line shows.

Sender signal 1, plain: This message failed the sender check (DMARC), so nothing proves it came from shop.example.

Sender signal 1, technical: DMARC failed for the From domain shop.example (RFC5322.From), so no aligned SPF or DKIM pass vouches for the author domain.

Spam signals, plain: These headers can't say. They carry no spam rating from the receiving system that this page can read.

Spam signals, technical: No spam filter result that this page can read was written by the receiver.

## fail with DKIM permerror

Plain headline: This message failed the sender check (DMARC). The signature couldn't be checked and it came from a server that bounce.mailer.example allows. Nothing that checked out matches shop.example, the domain in the From address.

Technical headline: DMARC at mx.receiver.example failed because DKIM for shop.example returned permerror and SPF passed for the Return-Path domain bounce.mailer.example (RFC5321.MailFrom), and nothing that passed aligns with the From domain shop.example (RFC5322.From).

Cause, plain: The signature on the message couldn't be checked, and nothing else proves it came from shop.example.

Cause, technical: The DKIM signature from shop.example could not be checked at mx.receiver.example (dkim=permerror): the key at s1._domainkey.shop.example is missing or unreadable, or the signature itself is malformed. SPF passed only for bounce.mailer.example, which is not shop.example.

Policy, plain: shop.example's DMARC setting asks providers to refuse fake mail. The recipient's email provider refused this message.

Policy, technical: shop.example publishes p=reject, which asks for failing mail to be refused, and mx.receiver.example refused this message (dis=REJECT).

Delivery, plain: shop.example's DMARC setting asks mail providers to refuse mail that fails this way. Expect the ones that follow it to refuse every message with this problem.

Delivery, technical: The DMARC record of shop.example carries p=reject, which asks receivers to reject mail that fails DMARC (RFC 9989 4.7). Every message that fails this way falls under it. A receiver is not required to honor the request, so some copies may still arrive.

Detail 1, plain: The signature from shop.example couldn't be checked.

Detail 1, technical: DKIM returned permerror for d=shop.example s=s1 (no key for signature).

Detail 2, plain: The sending server is approved, but by bounce.mailer.example, not by the sender's own domain.

Detail 2, technical: SPF passed for bounce.mailer.example, which does not align with shop.example. A pass on another domain does not count for DMARC.

Fix 1, plain: The key that checks this signature couldn't be read. Ask whoever manages the DNS for shop.example to compare the record named s1._domainkey.shop.example with what the service that sends this mail says it should be.

Fix 1, technical: Publish or repair the DKIM key at s1._domainkey.shop.example; mx.receiver.example could not use it.

Limit 1, plain: This page assumes the usual, looser domain match. A domain's DMARC setting can demand an exact match, and the headers don't show that setting.

Limit 1, technical: Alignment is computed in relaxed mode, the DMARC default, with strict mode beside it. adkim and aspf are set in the DMARC record, which is not in the headers.

Sender signals, plain: Maybe not. Treat this message with care.

Sender signals, technical: One signal says the author may not be who the From line shows.

Sender signal 1, plain: This message failed the sender check (DMARC), so nothing proves it came from shop.example.

Sender signal 1, technical: DMARC failed for the From domain shop.example (RFC5322.From), so no aligned SPF or DKIM pass vouches for the author domain.

Spam signals, plain: These headers can't say. They carry no spam rating from the receiving system that this page can read.

Spam signals, technical: No spam filter result that this page can read was written by the receiver.

## fail with DKIM temperror

Plain headline: This message failed the sender check (DMARC). The signature couldn't be checked and it came from a server that bounce.mailer.example allows. Nothing that checked out matches shop.example, the domain in the From address.

Technical headline: DMARC at mx.receiver.example failed because DKIM for shop.example returned temperror and SPF passed for the Return-Path domain bounce.mailer.example (RFC5321.MailFrom), and nothing that passed aligns with the From domain shop.example (RFC5322.From).

Cause, plain: The signature on the message couldn't be checked, and nothing else proves it came from shop.example.

Cause, technical: The DKIM signature from shop.example could not be checked at mx.receiver.example (dkim=temperror): a temporary DNS error kept it from fetching the key. SPF passed only for bounce.mailer.example, which is not shop.example.

Policy, plain: shop.example's DMARC setting asks providers to refuse fake mail. The recipient's email provider refused this message.

Policy, technical: shop.example publishes p=reject, which asks for failing mail to be refused, and mx.receiver.example refused this message (dis=REJECT).

Delivery: none written

Detail 1, plain: The signature from shop.example couldn't be checked.

Detail 1, technical: DKIM returned temperror for d=shop.example s=s1 (key query timeout).

Detail 2, plain: The sending server is approved, but by bounce.mailer.example, not by the sender's own domain.

Detail 2, technical: SPF passed for bounce.mailer.example, which does not align with shop.example. A pass on another domain does not count for DMARC.

Fix 1, plain: The key lookup failed for a temporary reason, which isn't a setup fault. If it keeps happening, ask whoever hosts the DNS for shop.example whether their servers were slow to answer.

Fix 1, technical: A temperror on the key query says nothing about the key. If it repeats, check that the nameservers for shop.example answer promptly and that s1._domainkey.shop.example resolves.

Limit 1, plain: This page assumes the usual, looser domain match. A domain's DMARC setting can demand an exact match, and the headers don't show that setting.

Limit 1, technical: Alignment is computed in relaxed mode, the DMARC default, with strict mode beside it. adkim and aspf are set in the DMARC record, which is not in the headers.

Sender signals, plain: Maybe not. Treat this message with care.

Sender signals, technical: One signal says the author may not be who the From line shows.

Sender signal 1, plain: This message failed the sender check (DMARC), so nothing proves it came from shop.example.

Sender signal 1, technical: DMARC failed for the From domain shop.example (RFC5322.From), so no aligned SPF or DKIM pass vouches for the author domain.

Spam signals, plain: These headers can't say. They carry no spam rating from the receiving system that this page can read.

Spam signals, technical: No spam filter result that this page can read was written by the receiver.

## fail computed, no DMARC result reported

Plain headline: The receiving system didn't record the sender check, so this page worked it out. This message fails the sender check (DMARC). It was signed by mailer.example and shop.example publishes no list of approved servers. Nothing that checked out matches shop.example, the domain in the From address.

Technical headline: mx.receiver.example recorded no DMARC result; worked out from the identifiers, DMARC fails because DKIM d=mailer.example s=m1 passed and SPF found no record for the Return-Path domain shop.example (RFC5321.MailFrom), and nothing that passed aligns with the From domain shop.example (RFC5322.From).

Cause, plain: The sender's domain publishes no list of approved servers, and nothing else proves the mail came from shop.example.

Cause, technical: DKIM passed only for mailer.example, which is not shop.example. shop.example publishes no SPF record, so SPF could not pass.

Policy, plain: The headers don't say what shop.example asks mail providers to do with fake mail.

Policy, technical: mx.receiver.example did not quote the DMARC policy of shop.example, so the headers do not show what a failure means for this domain. The record is in DNS, which this page does not read.

Delivery, plain: Gmail, Yahoo, and Microsoft's Outlook.com require bulk senders to pass the sender check (DMARC), and mail with this problem doesn't. Gmail and Outlook.com count bulk as 5,000 messages a day, and may refuse mail that falls short or send it to spam.

Delivery, technical: Bulk senders must pass DMARC with SPF or DKIM aligned, and nothing that passes here aligns with shop.example. Google's Email sender guidelines, Yahoo's Sender Best Practices, and Microsoft's Outlook.com requirements for high volume senders all say so. Google and Microsoft draw the line at 5,000 messages a day, and mail that falls short may be rejected or marked as spam.

Detail 1, plain: The message was signed, but by mailer.example, not by the sender's own domain.

Detail 1, technical: DKIM passed for d=mailer.example s=m1, which does not align with shop.example. A pass on another domain does not count for DMARC.

Fix 1, plain: In the settings of the service that sends this mail, turn on domain authentication for shop.example. The service gives you a few DNS records to add, and after that your mail is signed with your own domain instead of mailer.example.

Fix 1, technical: At the sending service, set up domain authentication for shop.example so the DKIM signature carries d=shop.example or a subdomain of it, instead of d=mailer.example.

Fix 2, plain: Ask whoever manages the DNS for shop.example to publish an SPF record listing the services that send your mail.

Fix 2, technical: Publish an SPF record for shop.example that lists the servers that send for it.

Limit 1, plain: This page assumes the usual, looser domain match. A domain's DMARC setting can demand an exact match, and the headers don't show that setting.

Limit 1, technical: Alignment is computed in relaxed mode, the DMARC default, with strict mode beside it. adkim and aspf are set in the DMARC record, which is not in the headers.

Sender signals, plain: Maybe not. Treat this message with care.

Sender signals, technical: One signal says the author may not be who the From line shows.

Sender signal 1, plain: This message failed the sender check (DMARC), so nothing proves it came from shop.example.

Sender signal 1, technical: DMARC failed for the From domain shop.example (RFC5322.From), so no aligned SPF or DKIM pass vouches for the author domain.

Spam signals, plain: These headers can't say. They carry no spam rating from the receiving system that this page can read.

Spam signals, technical: No spam filter result that this page can read was written by the receiver.

## fail through a mailing list

Plain headline: This message failed the sender check (DMARC) because it came through the mailing list club.list.example. The list changed the message, which broke the sender's signature, and sent it on under its own domain, list.example, not shop.example.

Technical headline: DMARC failed because the message came through the mailing list club.list.example, which changed it, breaking the DKIM signature from shop.example, and sent it on as list.example, which does not align with the From domain shop.example (RFC5322.From).

Cause, plain: The headers carry no record of how the message looked before the list, so this page can't confirm the sender's own setup. Lists break these checks by changing the message, for example by adding a footer.

Cause, technical: No record from before the list is in the headers, so this page cannot show that the message passed before the list changed it. Lists break signatures by tagging the subject or adding a footer.

Policy, plain: shop.example's DMARC setting asks providers to refuse fake mail. The recipient's email provider refused this message.

Policy, technical: shop.example publishes p=reject, which asks for failing mail to be refused, and mx.receiver.example refused this message (dis=REJECT).

Delivery, plain: Messages from shop.example that go through a list like this keep failing. shop.example's DMARC setting asks mail providers to refuse them.

Delivery, technical: Posts through a list that modifies messages keep failing DMARC (RFC 7960 3.2.3). The DMARC record of shop.example carries p=reject, which asks receivers to reject them (RFC 9989 4.7).

Detail 1, plain: The signature from shop.example didn't check out, because the mailing list changed the message.

Detail 1, technical: DKIM failed for d=shop.example s=s1. The message came through a mailing list, and lists change it enough to break the signature.

Detail 2, plain: The sending server is approved, but by list.example, not by the sender's own domain.

Detail 2, technical: SPF passed for list.example, which does not align with shop.example. A pass on another domain does not count for DMARC.

Fix 1, plain: If you sent this, your setup isn't the problem as far as these headers show. Lists that change messages break these checks. If you didn't send it, it may be forged to look like list mail.

Fix 1, technical: Nothing to change at shop.example on the strength of this message. Mail through a list that changes messages fails DMARC unless the list rewrites the From address or the receiver trusts the list's ARC seal. Nothing from before the list shows a pass, though, so if nobody at shop.example sent it, it is a forgery that borrowed a list's headers.

Fix 2, plain: If you run the list: have it send under its own address (it can keep the sender's name), or stop it adding a subject tag and a footer.

Fix 2, technical: If you run club.list.example: have the list rewrite the From address to its own; or stop tagging the subject and adding a footer; or ARC-seal outgoing mail so receivers that trust the seal see the result from before the list.

Limit 1, plain: This page assumes the usual, looser domain match. A domain's DMARC setting can demand an exact match, and the headers don't show that setting.

Limit 1, technical: Alignment is computed in relaxed mode, the DMARC default, with strict mode beside it. adkim and aspf are set in the DMARC record, which is not in the headers.

Sender signals, plain: Maybe not. Treat this message with care.

Sender signals, technical: One signal says the author may not be who the From line shows.

Sender signal 1, plain: This message failed the sender check (DMARC), so nothing proves it came from shop.example.

Sender signal 1, technical: DMARC failed for the From domain shop.example (RFC5322.From), so no aligned SPF or DKIM pass vouches for the author domain.

Spam signals, plain: These headers can't say. They carry no spam rating from the receiving system that this page can read.

Spam signals, technical: No spam filter result that this page can read was written by the receiver.

## fail through a mailing list that kept its record

Plain headline: This message failed the sender check (DMARC) because it came through the mailing list club.list.example. The list changed the message, which broke the sender's signature, and sent it on under its own domain, list.example, not shop.example.

Technical headline: DMARC failed because the message came through the mailing list club.list.example, which changed it, breaking the DKIM signature from shop.example, and sent it on as list.example, which does not align with the From domain shop.example (RFC5322.From).

Cause, plain: Before the list, the list's own server recorded that the message passed. The sender's setup looks fine. The list broke the checks by changing the message, for example by adding a footer.

Cause, technical: Before the list, mx.list.example recorded dkim=pass (shop.example), spf=pass (news@shop.example), and dmarc=pass (shop.example) in its Authentication-Results-Original field. The list's own server wrote that record and this page cannot verify it, but it shows the message passed on arrival. Lists break signatures by tagging the subject or adding a footer.

Policy, plain: shop.example's DMARC setting asks providers to refuse fake mail. The recipient's email provider refused this message.

Policy, technical: shop.example publishes p=reject, which asks for failing mail to be refused, and mx.receiver.example refused this message (dis=REJECT).

Delivery, plain: Messages from shop.example that go through a list like this keep failing. shop.example's DMARC setting asks mail providers to refuse them. Nothing here points to a problem with mail sent straight to people.

Delivery, technical: Posts through a list that modifies messages keep failing DMARC (RFC 7960 3.2.3). The DMARC record of shop.example carries p=reject, which asks receivers to reject them (RFC 9989 4.7). The list's record shows a pass on arrival, so nothing here counts against mail sent straight from shop.example.

Detail 1, plain: The signature from shop.example didn't check out, because the mailing list changed the message.

Detail 1, technical: DKIM failed for d=shop.example s=s1. The message came through a mailing list, and lists change it enough to break the signature.

Detail 2, plain: The sending server is approved, but by list.example, not by the sender's own domain.

Detail 2, technical: SPF passed for list.example, which does not align with shop.example. A pass on another domain does not count for DMARC.

Fix 1, plain: If you sent this, your setup isn't the problem as far as these headers show. Lists that change messages break these checks.

Fix 1, technical: Nothing to change at shop.example: its mail passed before the list. Mail through a list that changes messages fails DMARC unless the list rewrites the From address or the receiver trusts the list's ARC seal.

Fix 2, plain: If you run the list: have it send under its own address (it can keep the sender's name), or stop it adding a subject tag and a footer.

Fix 2, technical: If you run club.list.example: have the list rewrite the From address to its own; or stop tagging the subject and adding a footer; or ARC-seal outgoing mail so receivers that trust the seal see the result from before the list.

Limit 1, plain: This page assumes the usual, looser domain match. A domain's DMARC setting can demand an exact match, and the headers don't show that setting.

Limit 1, technical: Alignment is computed in relaxed mode, the DMARC default, with strict mode beside it. adkim and aspf are set in the DMARC record, which is not in the headers.

Sender signals, plain: Maybe not. Treat this message with care.

Sender signals, technical: One signal says the author may not be who the From line shows.

Sender signal 1, plain: This message failed the sender check (DMARC), so nothing proves it came from shop.example.

Sender signal 1, technical: DMARC failed for the From domain shop.example (RFC5322.From), so no aligned SPF or DKIM pass vouches for the author domain.

Spam signals, plain: These headers can't say. They carry no spam rating from the receiving system that this page can read.

Spam signals, technical: No spam filter result that this page can read was written by the receiver.

## fail with the receiver judging differently

Plain headline: This message failed the sender check (DMARC) even though it was signed by shop.example. The receiving system reported a failure the headers don't explain.

Technical headline: DMARC at mx.receiver.example failed even though DKIM d=shop.example s=s1 passed and aligns with the From domain shop.example.

Cause, plain: The checks line up, but the receiving system marked the message as failing, most likely under a rule of its own.

Cause, technical: The identifiers align and the receiver reported them as passing, yet it reported dmarc=fail. A local policy, or a result it did not write into these headers, is the likely reason.

Policy, plain: shop.example's DMARC setting asks providers to refuse fake mail. The recipient's email provider refused this message.

Policy, technical: shop.example publishes p=reject, which asks for failing mail to be refused, and mx.receiver.example refused this message (dis=REJECT).

Delivery: none written

Detail 1, plain: The message was signed by shop.example, which belongs to the sender.

Detail 1, technical: DKIM passed for d=shop.example s=s1, which aligns with shop.example.

Detail 2, plain: The headers don't say which domain the sending server was checked against.

Detail 2, technical: No SPF domain: there is no smtp.mailfrom, Received-SPF envelope-from or Return-Path to read it from.

Fix 1, plain: These headers don't show one clear fix. Send the same message to another mailbox, such as Gmail or Outlook, and compare.

Fix 1, technical: Nothing in these headers points at a single change. Compare with a copy of the same message delivered to a different mailbox provider.

Limit 1, plain: This page assumes the usual, looser domain match. A domain's DMARC setting can demand an exact match, and the headers don't show that setting.

Limit 1, technical: Alignment is computed in relaxed mode, the DMARC default, with strict mode beside it. adkim and aspf are set in the DMARC record, which is not in the headers.

Sender signals, plain: Maybe not. Treat this message with care.

Sender signals, technical: One signal says the author may not be who the From line shows.

Sender signal 1, plain: This message failed the sender check (DMARC), so nothing proves it came from shop.example.

Sender signal 1, technical: DMARC failed for the From domain shop.example (RFC5322.From), so no aligned SPF or DKIM pass vouches for the author domain.

Spam signals, plain: These headers can't say. They carry no spam rating from the receiving system that this page can read.

Spam signals, technical: No spam filter result that this page can read was written by the receiver.

## strict alignment suspected

Plain headline: This message failed the sender check (DMARC) although it was signed by a domain in the same organization as shop.example. The sender's DMARC setting probably demands an exact domain match.

Technical headline: DMARC at mx.receiver.example failed even though DKIM d=mail.shop.example s=s1 passed and aligns with the From domain shop.example in relaxed mode, so the DMARC record most likely requires strict alignment (adkim=s); the record itself is not in the headers.

Cause, plain: The sending domain's DMARC record probably demands an exact domain match, and this message only matches the wider organization.

Cause, technical: The receiver reported dmarc=fail and the identifiers align only in relaxed mode, so the record most likely sets adkim=s. The DMARC record decides; this page cannot read it without DNS.

Policy, plain: shop.example's DMARC setting asks providers to refuse fake mail. The recipient's email provider refused this message.

Policy, technical: shop.example publishes p=reject, which asks for failing mail to be refused, and mx.receiver.example refused this message (dis=REJECT).

Delivery, plain: shop.example's DMARC setting asks mail providers to refuse mail that fails this way. Expect the ones that follow it to refuse every message with this problem.

Delivery, technical: The DMARC record of shop.example carries p=reject, which asks receivers to reject mail that fails DMARC (RFC 9989 4.7). Every message that fails this way falls under it. A receiver is not required to honor the request, so some copies may still arrive.

Detail 1, plain: The message was signed by mail.shop.example, which belongs to the sender.

Detail 1, technical: DKIM passed for d=mail.shop.example s=s1, which aligns with shop.example in relaxed mode only.

Detail 2, plain: The sending server is approved, but by bounce.mailer.example, not by the sender's own domain.

Detail 2, technical: SPF passed for bounce.mailer.example, which does not align with shop.example. A pass on another domain does not count for DMARC.

Fix 1, plain: shop.example's DMARC record most likely requires an exact domain match. Either have the sending service sign with shop.example itself instead of mail.shop.example, or ask whoever manages the DNS for shop.example to allow subdomains (relaxed alignment). Check the record first. This page can't read it.

Fix 1, technical: The record most likely sets adkim=s. Sign with d=shop.example rather than a subdomain, or change the record to adkim=r. Confirm by reading _dmarc.shop.example; this page does not query DNS.

Limit 1, plain: This page assumes the usual, looser domain match. A domain's DMARC setting can demand an exact match, and the headers don't show that setting.

Limit 1, technical: Alignment is computed in relaxed mode, the DMARC default, with strict mode beside it. adkim and aspf are set in the DMARC record, which is not in the headers.

Limit 2, plain: This page works out where the sender's organization begins from its own short list, so the looser domain match is its best reading, not a certainty.

Limit 2, technical: The organizational domain shop.example comes from a short built in suffix list, not from DNS or the full Public Suffix List that receivers use. Relaxed alignment here rests on it.

Sender signals, plain: Maybe not. Treat this message with care.

Sender signals, technical: One signal says the author may not be who the From line shows.

Sender signal 1, plain: This message failed the sender check (DMARC), so nothing proves it came from shop.example.

Sender signal 1, technical: DMARC failed for the From domain shop.example (RFC5322.From), so no aligned SPF or DKIM pass vouches for the author domain.

Spam signals, plain: These headers can't say. They carry no spam rating from the receiving system that this page can read.

Spam signals, technical: No spam filter result that this page can read was written by the receiver.

## dmarc none, would pass

Plain headline: shop.example has no DMARC setting, so the sender check didn't apply. With one, this message would pass.

Technical headline: DMARC did not apply because mx.receiver.example found no DMARC record for shop.example; with one, this message would pass.

Cause, plain: Without a DMARC setting, nothing stops others from sending mail that claims to be from shop.example. This message is set up to pass once there's one.

Cause, technical: Without a DMARC record nothing ties SPF and DKIM to the From domain, so a receiver judges the message on its own signals, and anyone can put shop.example in a From address without failing a policy. With a record this message would pass, because DKIM d=shop.example s=s1 passed, and it aligns with the From domain shop.example (RFC5322.From).

Policy, plain: shop.example has no DMARC setting, so it gives mail providers no instructions for fake mail. Each provider decides for itself.

Policy, technical: shop.example publishes no DMARC policy, so nothing tells receivers what to do with mail that fails. Each receiver decides on its own.

Delivery, plain: Gmail, Yahoo, and Microsoft's Outlook.com require a DMARC setting from anyone who sends them mail in bulk. Gmail and Outlook.com count bulk as 5,000 messages a day, and may refuse mail that falls short or send it to spam.

Delivery, technical: Bulk senders must publish a DMARC record, at least p=none. Google's Email sender guidelines, Yahoo's Sender Best Practices, and Microsoft's Outlook.com requirements for high volume senders all say so. Google and Microsoft draw the line at 5,000 messages a day, and mail that falls short may be rejected or marked as spam.

Detail 1, plain: The message was signed by shop.example, which belongs to the sender.

Detail 1, technical: DKIM passed for d=shop.example s=s1, which aligns with shop.example.

Detail 2, plain: The sending server is approved, but by bounce.mailer.example, not by the sender's own domain.

Detail 2, technical: SPF passed for bounce.mailer.example, which does not align with shop.example. A pass on another domain does not count for DMARC.

Fix 1, plain: Ask whoever manages the DNS for shop.example to add a DMARC record. Start with the setting that only sends reports, and tighten it once the reports show all your real mail passes.

Fix 1, technical: Publish a DMARC record at _dmarc.shop.example with p=none and a rua= address, read the reports, then move to p=quarantine once every real source passes.

Fix 2, plain: Once the signature is fixed, you can also give the service that sends this mail a custom return address on shop.example. Services call it a custom return path or sending domain. It's optional.

Fix 2, technical: Second, after DKIM: set a custom Return-Path (bounce) domain under shop.example at the sending service so SPF aligns too.

Limit 1, plain: This page assumes the usual, looser domain match. A domain's DMARC setting can demand an exact match, and the headers don't show that setting.

Limit 1, technical: Alignment is computed in relaxed mode, the DMARC default, with strict mode beside it. adkim and aspf are set in the DMARC record, which is not in the headers.

Sender signals, plain: There's a reason to look twice.

Sender signals, technical: One signal says the author may not be who the From line shows.

Sender signal 1, plain: shop.example has no DMARC setting, so the headers can't prove the message came from shop.example.

Sender signal 1, technical: shop.example publishes no DMARC record, so no receiver is told to tie SPF or DKIM to the From domain.

Spam signals, plain: These headers can't say. They carry no spam rating from the receiving system that this page can read.

Spam signals, technical: No spam filter result that this page can read was written by the receiver.

## dmarc none, would fail

Plain headline: shop.example has no DMARC setting, so the sender check didn't apply. With one, this message would fail.

Technical headline: DMARC did not apply because mx.receiver.example found no DMARC record for shop.example; with one, this message would fail.

Cause, plain: Without a DMARC setting, nothing stops others from sending mail that claims to be from shop.example. This message wouldn't pass if one were added.

Cause, technical: Without a DMARC record nothing ties SPF and DKIM to the From domain, so a receiver judges the message on its own signals, and anyone can put shop.example in a From address without failing a policy. With a record this message would fail, because there was no DKIM signature and SPF passed for the Return-Path domain bounce.mailer.example (RFC5321.MailFrom), and nothing that passed aligns with the From domain shop.example (RFC5322.From).

Policy, plain: shop.example has no DMARC setting, so it gives mail providers no instructions for fake mail. Each provider decides for itself.

Policy, technical: shop.example publishes no DMARC policy, so nothing tells receivers what to do with mail that fails. Each receiver decides on its own.

Delivery, plain: Gmail, Yahoo, and Microsoft's Outlook.com require a DMARC setting from anyone who sends them mail in bulk. Gmail and Outlook.com count bulk as 5,000 messages a day, and may refuse mail that falls short or send it to spam.

Delivery, technical: Bulk senders must publish a DMARC record, at least p=none. Google's Email sender guidelines, Yahoo's Sender Best Practices, and Microsoft's Outlook.com requirements for high volume senders all say so. Google and Microsoft draw the line at 5,000 messages a day, and mail that falls short may be rejected or marked as spam.

Detail 1, plain: The sending server is approved, but by bounce.mailer.example, not by the sender's own domain.

Detail 1, technical: SPF passed for bounce.mailer.example, which does not align with shop.example. A pass on another domain does not count for DMARC.

Fix 1, plain: Ask whoever manages the DNS for shop.example to add a DMARC record. Start with the setting that only sends reports, and tighten it once the reports show all your real mail passes.

Fix 1, technical: Publish a DMARC record at _dmarc.shop.example with p=none and a rua= address, read the reports, then move to p=quarantine once every real source passes.

Fix 2, plain: Turn on email signing (DKIM) for shop.example in the settings of the service that sends this mail. It adds a digital signature with your domain to every message, and that signature still works when mail is forwarded.

Fix 2, technical: Turn on DKIM signing for shop.example at the sending service. Aligned DKIM lets DMARC pass, including after a forward.

Fix 3, plain: Once the signature is fixed, you can also give the service that sends this mail a custom return address on shop.example. Services call it a custom return path or sending domain. It's optional.

Fix 3, technical: Second, after DKIM: set a custom Return-Path (bounce) domain under shop.example at the sending service so SPF aligns too.

Limit 1, plain: This page assumes the usual, looser domain match. A domain's DMARC setting can demand an exact match, and the headers don't show that setting.

Limit 1, technical: Alignment is computed in relaxed mode, the DMARC default, with strict mode beside it. adkim and aspf are set in the DMARC record, which is not in the headers.

Sender signals, plain: There's a reason to look twice.

Sender signals, technical: One signal says the author may not be who the From line shows.

Sender signal 1, plain: shop.example has no DMARC setting, so the headers can't prove the message came from shop.example.

Sender signal 1, technical: shop.example publishes no DMARC record, so no receiver is told to tie SPF or DKIM to the From domain.

Spam signals, plain: These headers can't say. They carry no spam rating from the receiving system that this page can read.

Spam signals, technical: No spam filter result that this page can read was written by the receiver.

## dmarc bestguesspass

Plain headline: shop.example has no DMARC setting, so the sender check didn't apply. The message would pass if the domain had one.

Technical headline: DMARC did not apply: mx.receiver.example reported dmarc=bestguesspass, meaning shop.example has no DMARC record but the message would pass if it had one.

Cause, plain: Without a DMARC setting, nothing stops others from sending mail that claims to be from shop.example. This message is set up to pass once there's one.

Cause, technical: Without a DMARC record nothing ties SPF and DKIM to the From domain, so a receiver judges the message on its own signals, and anyone can put shop.example in a From address without failing a policy. With a record this message would pass, because SPF passed for the Return-Path domain shop.example (RFC5321.MailFrom), and it aligns with the From domain shop.example (RFC5322.From).

Policy, plain: shop.example has no DMARC setting, so it gives mail providers no instructions for fake mail. Each provider decides for itself.

Policy, technical: shop.example publishes no DMARC policy, so nothing tells receivers what to do with mail that fails. Each receiver decides on its own.

Delivery, plain: Gmail, Yahoo, and Microsoft's Outlook.com require a DMARC setting from anyone who sends them mail in bulk. Gmail and Outlook.com count bulk as 5,000 messages a day, and may refuse mail that falls short or send it to spam.

Delivery, technical: Bulk senders must publish a DMARC record, at least p=none. Google's Email sender guidelines, Yahoo's Sender Best Practices, and Microsoft's Outlook.com requirements for high volume senders all say so. Google and Microsoft draw the line at 5,000 messages a day, and mail that falls short may be rejected or marked as spam.

Detail 1, plain: The sending server is approved by shop.example, which belongs to the sender.

Detail 1, technical: SPF passed for shop.example, which aligns with shop.example.

Fix 1, plain: Ask whoever manages the DNS for shop.example to add a DMARC record. Start with the setting that only sends reports, and tighten it once the reports show all your real mail passes.

Fix 1, technical: Publish a DMARC record at _dmarc.shop.example with p=none and a rua= address, read the reports, then move to p=quarantine once every real source passes.

Fix 2, plain: Turn on email signing (DKIM) for shop.example in the settings of the service that sends this mail. It adds a digital signature with your domain to every message, and that signature still works when mail is forwarded.

Fix 2, technical: Turn on DKIM signing for shop.example at the sending service. Aligned DKIM lets DMARC pass, including after a forward.

Limit 1, plain: This page assumes the usual, looser domain match. A domain's DMARC setting can demand an exact match, and the headers don't show that setting.

Limit 1, technical: Alignment is computed in relaxed mode, the DMARC default, with strict mode beside it. adkim and aspf are set in the DMARC record, which is not in the headers.

Sender signals, plain: There's a reason to look twice.

Sender signals, technical: One signal says the author may not be who the From line shows.

Sender signal 1, plain: shop.example has no DMARC setting, so the headers can't prove the message came from shop.example.

Sender signal 1, technical: shop.example publishes no DMARC record, so no receiver is told to tie SPF or DKIM to the From domain.

Spam signals, plain: These headers can't say. They carry no spam rating from the receiving system that this page can read.

Spam signals, technical: No spam filter result that this page can read was written by the receiver.

## dmarc permerror

Plain headline: The sender check couldn't run because the DMARC record of shop.example is written wrong.

Technical headline: DMARC could not be evaluated because mx.receiver.example hit a permanent error reading the DMARC record for shop.example (dmarc=permerror).

Cause, plain: The record is there but broken, so mail systems treat the domain as if it had none.

Cause, technical: A permanent error means the record exists but cannot be read: a syntax mistake, a missing v=DMARC1, or more than one record. Computed from the identifiers, the message would pass.

Policy: none written

Delivery, plain: Until the record is fixed, shop.example counts as having no DMARC setting. Gmail, Yahoo, and Microsoft's Outlook.com require one from anyone who sends them mail in bulk. Gmail and Outlook.com count bulk as 5,000 messages a day, and may refuse mail that falls short or send it to spam.

Delivery, technical: A receiver applies no DMARC processing when the record cannot be parsed (RFC 9989), so shop.example stands as a domain with no record until it is repaired. Bulk senders must publish one. Google's Email sender guidelines, Yahoo's Sender Best Practices, and Microsoft's Outlook.com requirements for high volume senders all say so. Google and Microsoft draw the line at 5,000 messages a day, and mail that falls short may be rejected or marked as spam.

Detail 1, plain: The sending server is approved by shop.example, which belongs to the sender.

Detail 1, technical: SPF passed for shop.example, which aligns with shop.example.

Fix 1, plain: The sender's DMARC record is written wrong, so mail systems ignore it. Ask whoever manages the DNS for shop.example to check the record named _dmarc.shop.example for typos, or for a second copy that should be deleted.

Fix 1, technical: Fix the DMARC record at _dmarc.shop.example: mx.receiver.example could not parse it. Look for a mistyped tag, a missing v=DMARC1 at the start, or two records at the same name.

Fix 2, plain: Turn on email signing (DKIM) for shop.example in the settings of the service that sends this mail. It adds a digital signature with your domain to every message, and that signature still works when mail is forwarded.

Fix 2, technical: Turn on DKIM signing for shop.example at the sending service. Aligned DKIM lets DMARC pass, including after a forward.

Limit 1, plain: This page assumes the usual, looser domain match. A domain's DMARC setting can demand an exact match, and the headers don't show that setting.

Limit 1, technical: Alignment is computed in relaxed mode, the DMARC default, with strict mode beside it. adkim and aspf are set in the DMARC record, which is not in the headers.

Sender signals, plain: There's a reason to look twice.

Sender signals, technical: One signal says the author may not be who the From line shows.

Sender signal 1, plain: The sender check (DMARC) couldn't run for shop.example, so the headers can't prove who sent this.

Sender signal 1, technical: DMARC could not be evaluated for shop.example, so the result says nothing about the author domain.

Spam signals, plain: These headers can't say. They carry no spam rating from the receiving system that this page can read.

Spam signals, technical: No spam filter result that this page can read was written by the receiver.

## dmarc temperror

Plain headline: The sender check couldn't run because looking up the DMARC record of shop.example failed for a temporary reason.

Technical headline: DMARC could not be evaluated because mx.receiver.example hit a temporary DNS error looking up the DMARC record for shop.example (dmarc=temperror).

Cause, plain: The lookup failed this time. The next one may work.

Cause, technical: A temporary error says nothing about the record itself. Computed from the identifiers, the message would fail.

Policy: none written

Delivery: none written

Detail 1, plain: The sending server is approved, but by bounce.mailer.example, not by the sender's own domain.

Detail 1, technical: SPF passed for bounce.mailer.example, which does not align with shop.example. A pass on another domain does not count for DMARC.

Fix 1, plain: The check failed for a temporary reason. If it keeps happening, ask whoever hosts the DNS for shop.example whether their servers had trouble.

Fix 1, technical: The DMARC lookup failed for a temporary reason, so there is nothing to fix from these headers. If it repeats, check the DNS hosting of shop.example.

Fix 2, plain: Turn on email signing (DKIM) for shop.example in the settings of the service that sends this mail. It adds a digital signature with your domain to every message, and that signature still works when mail is forwarded.

Fix 2, technical: Turn on DKIM signing for shop.example at the sending service. Aligned DKIM lets DMARC pass, including after a forward.

Fix 3, plain: Once the signature is fixed, you can also give the service that sends this mail a custom return address on shop.example. Services call it a custom return path or sending domain. It's optional.

Fix 3, technical: Second, after DKIM: set a custom Return-Path (bounce) domain under shop.example at the sending service so SPF aligns too.

Limit 1, plain: This page assumes the usual, looser domain match. A domain's DMARC setting can demand an exact match, and the headers don't show that setting.

Limit 1, technical: Alignment is computed in relaxed mode, the DMARC default, with strict mode beside it. adkim and aspf are set in the DMARC record, which is not in the headers.

Sender signals, plain: There's a reason to look twice.

Sender signals, technical: One signal says the author may not be who the From line shows.

Sender signal 1, plain: The sender check (DMARC) couldn't run for shop.example, so the headers can't prove who sent this.

Sender signal 1, technical: DMARC could not be evaluated for shop.example, so the result says nothing about the author domain.

Spam signals, plain: These headers can't say. They carry no spam rating from the receiving system that this page can read.

Spam signals, technical: No spam filter result that this page can read was written by the receiver.

## dmarc result outside RFC 9989

Plain headline: The receiving system recorded a sender check result this page doesn't know.

Technical headline: mx.receiver.example reported dmarc=policy, a result RFC 9989 does not define, so it is shown as written.

Cause, plain: The details below show what was checked.

Cause, technical: The identifiers are in the details below; the page does not guess what the receiver meant.

Policy: none written

Delivery: none written

Detail 1, plain: The sending server is approved, but by bounce.mailer.example, not by the sender's own domain.

Detail 1, technical: SPF passed for bounce.mailer.example, which does not align with shop.example. A pass on another domain does not count for DMARC.

Fix 1, plain: Send the same message to a Gmail or Outlook mailbox and copy the headers from there. Those services write down the results this page needs.

Fix 1, technical: Get the same message from a Gmail or Microsoft 365 mailbox; both record SPF, DKIM and DMARC results.

Limit 1, plain: This page assumes the usual, looser domain match. A domain's DMARC setting can demand an exact match, and the headers don't show that setting.

Limit 1, technical: Alignment is computed in relaxed mode, the DMARC default, with strict mode beside it. adkim and aspf are set in the DMARC record, which is not in the headers.

Sender signals, plain: These headers can't say. They hold no check results from a receiving mail system.

Sender signals, technical: No receiver's results are in these headers, so nothing here speaks for or against the author.

Spam signals, plain: These headers can't say. They carry no spam rating from the receiving system that this page can read.

Spam signals, technical: No spam filter result that this page can read was written by the receiver.

## forwarded with arc=pass

Plain headline: This message failed the sender check (DMARC) because it was forwarded by forward.example. It passed before the forward, and the forward broke it.

Technical headline: DMARC at mx.receiver.example failed because the message was forwarded by forward.example: before the forward, mx.forward.example recorded spf=pass (orders@shop.example), dkim=pass (shop.example), and dmarc=pass (shop.example), and after it DKIM d=shop.example s=s1 failed verification and SPF soft failed for the Return-Path domain shop.example (RFC5321.MailFrom).

Cause, plain: The sender's setup is fine. The forward re-sent the message from a server the sender's list doesn't include and changed it on the way, which broke the signature.

Cause, technical: The failure belongs to the forward, not to the sender. The message passed on arrival at mx.forward.example. The forward broke SPF: it sent the message on from its own server, which the SPF record of shop.example does not authorize (spf=softfail). It also broke the DKIM signature from shop.example by changing the message.

Policy, plain: shop.example's DMARC setting asks providers to refuse fake mail. The recipient's email provider refused this message.

Policy, technical: shop.example publishes p=reject, which asks for failing mail to be refused, and mx.receiver.example refused this message (dis=REJECT).

Delivery, plain: Copies that go through this forward can keep failing at mail providers that don't accept the forwarding service's record. shop.example's DMARC setting asks those providers to refuse them. Mail sent straight from shop.example isn't affected.

Delivery, technical: Copies that go through this forward keep failing DMARC wherever the forwarder's ARC chain is not accepted. RFC 7960 2.2 describes how forwarding breaks SPF. The DMARC record of shop.example carries p=reject, which asks those receivers to reject them (RFC 9989 4.7). Mail sent straight from shop.example is not affected.

Detail 1, plain: The signature from shop.example didn't check out, most likely because the forward changed the message.

Detail 1, technical: DKIM failed for d=shop.example s=s1. The message was forwarded, and forwarders often change it enough to break the signature.

Detail 2, plain: shop.example's list of approved servers doesn't include the server that sent this, and asks receivers to treat that as suspicious rather than refuse it.

Detail 2, technical: SPF soft failed for shop.example. A forward sends from the forwarder's own server, which the sender's SPF record does not list.

Fix 1, plain: The sender did nothing wrong. If you set up this forward, ask whoever runs the receiving mailbox to trust the forwarding service (forward.example). In Microsoft 365, an administrator adds it under Trusted ARC sealers in the Defender portal.

Fix 1, technical: Nothing at the sender fixes a forward. If the forward is yours, have the final mailbox trust the forwarder's ARC seal: Gmail weighs ARC on its own; Microsoft 365 honors it only for sealers an admin adds as trusted ARC sealers in the Defender portal.

Fix 2, plain: If you didn't set up this forward, there's nothing to change. Ask for a copy sent straight to you to check the sender.

Fix 2, technical: If the forward is not yours, authentication worked as designed. Judge the sender by a copy delivered straight to the mailbox.

Limit 1, plain: This page assumes the usual, looser domain match. A domain's DMARC setting can demand an exact match, and the headers don't show that setting.

Limit 1, technical: Alignment is computed in relaxed mode, the DMARC default, with strict mode beside it. adkim and aspf are set in the DMARC record, which is not in the headers.

Limit 2, plain: This page can't confirm the forwarding service's own record, so what it saw before the forward is taken on its word.

Limit 2, technical: ARC seals are not verified here, so the results before the forward are the forwarder's own record; mx.receiver.example reported arc=pass, which means it did verify them.

Sender signals, plain: Yes, as far as the headers show.

Sender signals, technical: No flag fired: DMARC passed before the forward for shop.example, and the display name, Reply-To, and From domain raise nothing.

Spam signals, plain: These headers can't say. They carry no spam rating from the receiving system that this page can read.

Spam signals, technical: No spam filter result that this page can read was written by the receiver.

Signals, nothing fired, plain: Nothing in the headers points to forgery or spam. That covers the headers only, because this page doesn't judge the message text, links, or attachments.

Signals, nothing fired, technical: Nothing in the headers points to forgery or spam. That is a statement about the headers only: the body, links and attachments are not examined.

## forwarded, noted but not relied on

Plain headline: This message failed the sender check (DMARC). The signature didn't check out and the sending server isn't on the sender's list of approved servers. Nothing proved it came from shop.example.

Technical headline: DMARC at mx.receiver.example failed because DKIM d=shop.example s=s1 failed verification and SPF soft failed for the Return-Path domain shop.example (RFC5321.MailFrom), so no identifier passed for the From domain shop.example (RFC5322.From).

Cause, plain: The message was changed after it was signed, or the signature doesn't match the sender's published key.

Cause, technical: The DKIM signature from shop.example did not verify at mx.receiver.example: something changed the signed part of the message after signing, or the key in DNS does not match. The SPF record of shop.example does not authorize the server that handed the message over and asks receivers to treat it as suspicious rather than fail it outright (softfail), as mx.receiver.example reported.

Policy, plain: shop.example's DMARC setting asks providers to refuse fake mail. The recipient's email provider refused this message.

Policy, technical: shop.example publishes p=reject, which asks for failing mail to be refused, and mx.receiver.example refused this message (dis=REJECT).

Delivery: none written

Detail 1, plain: The signature from shop.example didn't check out, most likely because the forward changed the message.

Detail 1, technical: DKIM failed for d=shop.example s=s1. The message was forwarded, and forwarders often change it enough to break the signature.

Detail 2, plain: shop.example's list of approved servers doesn't include the server that sent this, and asks receivers to treat that as suspicious rather than refuse it.

Detail 2, technical: SPF soft failed for shop.example. A forward sends from the forwarder's own server, which the sender's SPF record does not list.

Detail 3, plain: The forwarder claims the message passed before it was forwarded, but its record doesn't hold up, so this page doesn't rely on it.

Detail 3, technical: The forwarder's record says before the forward, mx.forward.example recorded spf=pass (orders@shop.example), dkim=pass (shop.example), and dmarc=pass (shop.example), but mx.receiver.example did not report arc=pass, and this page does not verify ARC seals, so that record is not relied on and the failure is not blamed on the forward.

Fix 1, plain: Ask for a copy sent straight to you, without the forward, and check that one. The forwarding service says the message passed before it forwarded it, but nothing here confirms that.

Fix 1, technical: Judge the sender by a copy delivered straight to the mailbox. The forwarder's record shows a pass before the forward, but the receiver did not confirm it, so this failure could come from the forward or from a forgery.

Limit 1, plain: This page assumes the usual, looser domain match. A domain's DMARC setting can demand an exact match, and the headers don't show that setting.

Limit 1, technical: Alignment is computed in relaxed mode, the DMARC default, with strict mode beside it. adkim and aspf are set in the DMARC record, which is not in the headers.

Limit 2, plain: This page can't confirm the forwarding service's own record, so what it saw before the forward is taken on its word.

Limit 2, technical: ARC seals are not verified here, so the results before the forward are the forwarder's own record.

Sender signals, plain: Maybe not. Treat this message with care.

Sender signals, technical: One signal says the author may not be who the From line shows.

Sender signal 1, plain: This message failed the sender check (DMARC), so nothing proves it came from shop.example.

Sender signal 1, technical: DMARC failed for the From domain shop.example (RFC5322.From), so no aligned SPF or DKIM pass vouches for the author domain.

Spam signals, plain: These headers can't say. They carry no spam rating from the receiving system that this page can read.

Spam signals, technical: No spam filter result that this page can read was written by the receiver.

## forwarded, already failing before the forward

Plain headline: This message failed the sender check (DMARC). The signature wasn't checked and it came from a server that forward.example allows. Nothing that checked out matches shop.example, the domain in the From address.

Technical headline: DMARC at mx.receiver.example failed because the DKIM signature from shop.example has no recorded result and SPF passed for the Return-Path domain forward.example (RFC5321.MailFrom), and nothing that passed aligns with the From domain shop.example (RFC5322.From).

Cause, plain: The message failed the check before it was ever forwarded, so the problem is with the sender, not the forward.

Cause, technical: The message was already failing before the forward: mx.forward.example recorded spf=fail (orders@shop.example) and dmarc=fail (shop.example). SPF now passes only for the forwarder's domain forward.example, which does not count for shop.example.

Policy, plain: shop.example's DMARC setting asks providers to refuse fake mail. The recipient's email provider refused this message.

Policy, technical: shop.example publishes p=reject, which asks for failing mail to be refused, and mx.receiver.example refused this message (dis=REJECT).

Delivery, plain: shop.example's DMARC setting asks mail providers to refuse mail that fails this way. Expect the ones that follow it to refuse every message with this problem.

Delivery, technical: The DMARC record of shop.example carries p=reject, which asks receivers to reject mail that fails DMARC (RFC 9989 4.7). Every message that fails this way falls under it. A receiver is not required to honor the request, so some copies may still arrive.

Detail 1, plain: One signature on the message wasn't checked by the receiver.

Detail 1, technical: DKIM-Signature d=shop.example s=s1 carries no result from the receiver.

Detail 2, plain: The sending server is approved, but by forward.example, not by the sender's own domain.

Detail 2, technical: SPF passed for forward.example, which does not align with shop.example. A pass on another domain does not count for DMARC.

Fix 1, plain: The problem started before the forward. If shop.example didn't send this message, it's forged, and the failed check is working as it should.

Fix 1, technical: Look at the sender, not the forward: the message failed before it was forwarded. If shop.example did not send it, it is forged and the DMARC failure is correct.

Limit 1, plain: This page assumes the usual, looser domain match. A domain's DMARC setting can demand an exact match, and the headers don't show that setting.

Limit 1, technical: Alignment is computed in relaxed mode, the DMARC default, with strict mode beside it. adkim and aspf are set in the DMARC record, which is not in the headers.

Limit 2, plain: This page can't confirm the forwarding service's own record, so what it saw before the forward is taken on its word.

Limit 2, technical: ARC seals are not verified here, so the results before the forward are the forwarder's own record; mx.receiver.example reported arc=pass, which means it did verify them.

Sender signals, plain: Maybe not. Treat this message with care.

Sender signals, technical: One signal says the author may not be who the From line shows.

Sender signal 1, plain: This message failed the sender check (DMARC), so nothing proves it came from shop.example.

Sender signal 1, technical: DMARC failed for the From domain shop.example (RFC5322.From), so no aligned SPF or DKIM pass vouches for the author domain.

Spam signals, plain: These headers can't say. They carry no spam rating from the receiving system that this page can read.

Spam signals, technical: No spam filter result that this page can read was written by the receiver.

## pass reported with DKIM nothing backs

Plain headline: This message passed the sender check (DMARC). It was signed by shop.example, the domain in the From address, and came from a server it allows.

Technical headline: DMARC at mx.receiver.example passed because DKIM d=shop.example s=s1 passed and SPF passed for the Return-Path domain shop.example (RFC5321.MailFrom), and both align with the From domain shop.example (RFC5322.From).

Cause, plain: A message passes when it's signed by, or sent for, the domain in its From address, and this one was.

Cause, technical: For shop.example, both SPF and DKIM pass and align, so the message still passes after a forward that breaks SPF.

Policy, plain: The message passed, so the sender's DMARC setting didn't come into play.

Policy, technical: shop.example publishes p=reject, which asks for failing mail to be refused. This message passed, so the policy did not come into play.

Delivery: none written

Detail 1, plain: The message was signed by shop.example, which belongs to the sender.

Detail 1, technical: DKIM passed for d=shop.example s=s1, which aligns with shop.example.

Detail 2, plain: The sending server is approved by shop.example, which belongs to the sender.

Detail 2, technical: SPF passed for shop.example, which aligns with shop.example.

Limit 1, plain: This page assumes the usual, looser domain match. A domain's DMARC setting can demand an exact match, and the headers don't show that setting.

Limit 1, technical: Alignment is computed in relaxed mode, the DMARC default, with strict mode beside it. adkim and aspf are set in the DMARC record, which is not in the headers.

Limit 2, plain: The sender could have written these check results. They say the message carries a valid digital signature (DKIM), but the headers hold no signature to back that.

Limit 2, technical: The only trusted Authentication-Results field (authserv-id mx.receiver.example) sits below the receiver's only Received stamp, where the sender could have written it. It reports dkim=pass, but the headers hold no DKIM-Signature, so nothing here backs that pass.

Sender signals, plain: Yes, as far as the headers show.

Sender signals, technical: No flag fired: DMARC passed for shop.example, and the display name, Reply-To, and From domain raise nothing.

Spam signals, plain: These headers can't say. They carry no spam rating from the receiving system that this page can read.

Spam signals, technical: No spam filter result that this page can read was written by the receiver.

Signals, nothing fired, plain: Nothing in the headers points to forgery or spam. That covers the headers only, because this page doesn't judge the message text, links, or attachments.

Signals, nothing fired, technical: Nothing in the headers points to forgery or spam. That is a statement about the headers only: the body, links and attachments are not examined.

## no Authentication-Results

Plain headline: The receiving mail system didn't record its checks in these headers.

Technical headline: Nothing can be judged because there is no Authentication-Results field: receiver.example recorded no SPF, DKIM or DMARC result here.

Cause, plain: Without the receiver's own record there's nothing trustworthy to read.

Cause, technical: Some servers skip Authentication-Results, and some mail programs strip it when exporting. Results written by anyone else could be forged, so they are not used.

Policy: none written

Delivery: none written

Detail 1, plain: The message carries a signature, but no receiving system recorded checking it.

Detail 1, technical: DKIM signatures present, not checked by any receiver here: d=shop.example (would align).

Fix 1, plain: Send the same message to a Gmail or Outlook mailbox and copy the headers from there. Those services write down the results this page needs.

Fix 1, technical: Get the same message from a Gmail or Microsoft 365 mailbox; both record SPF, DKIM and DMARC results.

Sender signals, plain: These headers can't say. They hold no check results from a receiving mail system.

Sender signals, technical: No receiver's results are in these headers, so nothing here speaks for or against the author.

Spam signals, plain: These headers can't say. They carry no spam rating from the receiving system that this page can read.

Spam signals, technical: No spam filter result that this page can read was written by the receiver.

## Authentication-Results with no results

Plain headline: The receiving mail system recorded no checks for this message.

Technical headline: mx.receiver.example wrote Authentication-Results but recorded no SPF, DKIM or DMARC result in it, so there is nothing to judge.

Cause, plain: There's nothing in the record to go on.

Cause, technical: The field is there, but it lists no method this page reads (it reports none).

Policy: none written

Delivery: none written

Fix 1, plain: Send the same message to a Gmail or Outlook mailbox and copy the headers from there. Those services write down the results this page needs.

Fix 1, technical: Get the same message from a Gmail or Microsoft 365 mailbox; both record SPF, DKIM and DMARC results.

Limit 1, plain: This page assumes the usual, looser domain match. A domain's DMARC setting can demand an exact match, and the headers don't show that setting.

Limit 1, technical: Alignment is computed in relaxed mode, the DMARC default, with strict mode beside it. adkim and aspf are set in the DMARC record, which is not in the headers.

Sender signals, plain: These headers can't say. They hold no check results from a receiving mail system.

Sender signals, technical: No receiver's results are in these headers, so nothing here speaks for or against the author.

Spam signals, plain: These headers can't say. They carry no spam rating from the receiving system that this page can read.

Spam signals, technical: No spam filter result that this page can read was written by the receiver.

## untrusted Authentication-Results claims a pass

Plain headline: This message failed the sender check (DMARC). It was signed by mailer.example and the sending server isn't on the sender's list of approved servers. Nothing that checked out matches shop.example, the domain in the From address.

Technical headline: DMARC at mx.receiver.example failed because DKIM d=mailer.example s=m1 passed and SPF failed for the Return-Path domain shop.example (RFC5321.MailFrom), and nothing that passed aligns with the From domain shop.example (RFC5322.From).

Cause, plain: The server that sent this isn't on the sender's list of approved servers (SPF).

Cause, technical: DKIM passed only for mailer.example, which is not shop.example. The server that handed the message over is not authorized by the SPF record of shop.example, as mx.receiver.example reported.

Policy, plain: shop.example's DMARC setting asks providers to refuse fake mail. The recipient's email provider refused this message.

Policy, technical: shop.example publishes p=reject, which asks for failing mail to be refused, and mx.receiver.example refused this message (dis=REJECT).

Delivery, plain: shop.example's DMARC setting asks mail providers to refuse mail that fails this way. Expect the ones that follow it to refuse every message with this problem.

Delivery, technical: The DMARC record of shop.example carries p=reject, which asks receivers to reject mail that fails DMARC (RFC 9989 4.7). Every message that fails this way falls under it. A receiver is not required to honor the request, so some copies may still arrive.

Detail 1, plain: The message was signed, but by mailer.example, not by the sender's own domain.

Detail 1, technical: DKIM passed for d=mailer.example s=m1, which does not align with shop.example. A pass on another domain does not count for DMARC.

Fix 1, plain: In the settings of the service that sends this mail, turn on domain authentication for shop.example. The service gives you a few DNS records to add, and after that your mail is signed with your own domain instead of mailer.example.

Fix 1, technical: At the sending service, set up domain authentication for shop.example so the DKIM signature carries d=shop.example or a subdomain of it, instead of d=mailer.example.

Fix 2, plain: If you sent this, ask whoever manages the DNS for shop.example to add the service that sends this mail to its list of allowed servers (the SPF record). The service's setup page gives the exact entry. If you didn't send it, someone else used your domain and the check correctly failed it.

Fix 2, technical: If this is your mail, add the sending service to the SPF record of shop.example. If it is not, the SPF failure is correct.

Flag 1, plain: One set of results in the headers claims the message passed, but the receiving system didn't write it, so it's ignored.

Flag 1, technical: An Authentication-Results field the receiver did not write claims dmarc=pass. It is ignored here: the sender or a hop before the receiver could have written it.

Limit 1, plain: This page assumes the usual, looser domain match. A domain's DMARC setting can demand an exact match, and the headers don't show that setting.

Limit 1, technical: Alignment is computed in relaxed mode, the DMARC default, with strict mode beside it. adkim and aspf are set in the DMARC record, which is not in the headers.

Sender signals, plain: Maybe not. Treat this message with care.

Sender signals, technical: Two signals say the author may not be who the From line shows.

Sender signal 1, plain: This message failed the sender check (DMARC), so nothing proves it came from shop.example.

Sender signal 1, technical: DMARC failed for the From domain shop.example (RFC5322.From), so no aligned SPF or DKIM pass vouches for the author domain.

Sender signal 2, plain: One set of results in the headers claims the message passed, but the receiving system didn't write it, so it's ignored.

Sender signal 2, technical: An Authentication-Results field the receiver did not write claims dmarc=pass. It is ignored here: the sender or a hop before the receiver could have written it.

Spam signals, plain: These headers can't say. They carry no spam rating from the receiving system that this page can read.

Spam signals, technical: No spam filter result that this page can read was written by the receiver.

## no Received

Plain headline: This is the sender's own copy, so no mail system has checked it yet.

Technical headline: Nothing was checked because these headers have no Received fields: this is a sent or draft copy, and SPF, DKIM and DMARC are checked only by a receiving server.

Cause, plain: The checks happen when a message arrives, and this copy hasn't arrived anywhere.

Cause, technical: A receiver writes Authentication-Results when it accepts the message. This copy was not received, so it has none.

Policy: none written

Delivery: none written

Detail 1, plain: The message carries a signature, but no receiving system recorded checking it.

Detail 1, technical: DKIM signatures present, not checked by any receiver here: d=shop.example (would align).

Fix 1, plain: These headers come from a sent or draft copy. Open the message in the recipient's mailbox and copy its headers from there.

Fix 1, technical: Paste the headers of the copy the recipient received. This copy did not pass through a receiving server, so nothing was checked.

Sender signals, plain: These headers can't say. They hold no check results from a receiving mail system.

Sender signals, technical: No receiver's results are in these headers, so nothing here speaks for or against the author.

Spam signals, plain: These headers can't say. They carry no spam rating from the receiving system that this page can read.

Spam signals, technical: No spam filter result that this page can read was written by the receiver.

## two From fields

Plain headline: This page can't check who sent the message, because the message names more than one sender.

Technical headline: DMARC cannot be judged because the message carries two From fields, so there is no single author domain to align with.

Cause, plain: The receiving system recorded a result, but the headers don't say which sender it checked.

Cause, technical: DMARC checks one author domain. mx.receiver.example still reported dmarc=pass for header.from=shop.example, but which address it judged is not in the headers.

Policy: none written

Delivery: none written

Fix 1, plain: Don't trust this message. It names more than one sender, which is a common trick in forged mail.

Fix 1, technical: Treat the message as suspicious: with no single From domain, DMARC cannot protect the recipient.

Sender signals, plain: Maybe not. Treat this message with care.

Sender signals, technical: One signal says the author may not be who the From line shows.

Sender signal 1, plain: The message names more than one sender, which is a common trick in forged mail.

Sender signal 1, technical: There is no single From domain, so DMARC protects no author domain here.

Spam signals, plain: These headers can't say. They carry no spam rating from the receiving system that this page can read.

Spam signals, technical: No spam filter result that this page can read was written by the receiver.

## From naming two domains

Plain headline: This page can't check who sent the message, because the sender line names addresses at more than one domain.

Technical headline: DMARC cannot be judged because the From field names addresses in two domains (shop.example and bank.example), so there is no single author domain to align with.

Cause, plain: Without one clear sender there's nothing to check.

Cause, technical: DMARC checks one author domain. Nothing is computed from any of the addresses.

Policy: none written

Delivery: none written

Fix 1, plain: Don't trust this message. It names more than one sender, which is a common trick in forged mail.

Fix 1, technical: Treat the message as suspicious: with no single From domain, DMARC cannot protect the recipient.

Sender signals, plain: Maybe not. Treat this message with care.

Sender signals, technical: One signal says the author may not be who the From line shows.

Sender signal 1, plain: The message names more than one sender, which is a common trick in forged mail.

Sender signal 1, technical: There is no single From domain, so DMARC protects no author domain here.

Spam signals, plain: These headers can't say. They carry no spam rating from the receiving system that this page can read.

Spam signals, technical: No spam filter result that this page can read was written by the receiver.

## no From

Plain headline: This page can't check who sent the message, because the sender's address is missing.

Technical headline: DMARC cannot be judged because there is no usable From address, so there is no single author domain to align with.

Cause, plain: Without one clear sender there's nothing to check.

Cause, technical: DMARC aligns SPF and DKIM with the author domain, and without one there is nothing to align with. Nothing is computed from any of the addresses.

Policy: none written

Delivery: none written

Fix 1, plain: The sender's address is missing, so copy the full headers again and make sure the From line is included.

Fix 1, technical: Paste the complete header block; there is no usable From address to check against.

Sender signals, plain: These headers can't say. They hold no check results from a receiving mail system.

Sender signals, technical: No receiver's results are in these headers, so nothing here speaks for or against the author.

Spam signals, plain: These headers can't say. They carry no spam rating from the receiving system that this page can read.

Spam signals, technical: No spam filter result that this page can read was written by the receiver.

## display name impersonation

Plain headline: This message passed the sender check (DMARC). It was signed by notify.example, the domain in the From address, and came from a server it allows.

Technical headline: DMARC at mx.receiver.example passed because DKIM d=notify.example s=n1 passed and SPF passed for the Return-Path domain notify.example (RFC5321.MailFrom), and both align with the From domain notify.example (RFC5322.From).

Cause, plain: A message passes when it's signed by, or sent for, the domain in its From address, and this one was.

Cause, technical: For notify.example, both SPF and DKIM pass and align, so the message still passes after a forward that breaks SPF.

Policy, plain: The headers don't say what notify.example asks mail providers to do with fake mail.

Policy, technical: mx.receiver.example did not quote the DMARC policy of notify.example, so the headers do not show what a failure means for this domain. The record is in DNS, which this page does not read.

Delivery: none written

Detail 1, plain: The message was signed by notify.example, which belongs to the sender.

Detail 1, technical: DKIM passed for d=notify.example s=n1, which aligns with notify.example.

Detail 2, plain: The sending server is approved by notify.example, which belongs to the sender.

Detail 2, technical: SPF passed for notify.example, which aligns with notify.example.

Flag 1, plain: The name shown for the sender contains an address at bank.example, but the message comes from notify.example. Forged mail often does this.

Flag 1, technical: The display name shows an address at bank.example, while the real From domain is notify.example. That is a common impersonation layout.

Limit 1, plain: This page assumes the usual, looser domain match. A domain's DMARC setting can demand an exact match, and the headers don't show that setting.

Limit 1, technical: Alignment is computed in relaxed mode, the DMARC default, with strict mode beside it. adkim and aspf are set in the DMARC record, which is not in the headers.

Sender signals, plain: Maybe not. Treat this message with care.

Sender signals, technical: One signal says the author may not be who the From line shows.

Sender signal 1, plain: The name shown for the sender contains an address at bank.example, but the message comes from notify.example. Forged mail often does this.

Sender signal 1, technical: The display name shows an address at bank.example, while the real From domain is notify.example. That is a common impersonation layout.

Spam signals, plain: These headers can't say. They carry no spam rating from the receiving system that this page can read.

Spam signals, technical: No spam filter result that this page can read was written by the receiver.

## Microsoft action oreject

Plain headline: This message failed the sender check (DMARC). It carried no signature and the sending server isn't on the sender's list of approved servers. Nothing proved it came from shop.example.

Technical headline: DMARC at Microsoft 365 failed because there was no DKIM signature and SPF failed for the Return-Path domain shop.example (RFC5321.MailFrom), so no identifier passed for the From domain shop.example (RFC5322.From).

Cause, plain: The server that sent this isn't on the sender's list of approved servers (SPF). Microsoft's own sender check failed it too.

Cause, technical: There is no DKIM signature, so DMARC depends on SPF alone. The server that handed the message over is not authorized by the SPF record of shop.example, as Microsoft 365 reported. Microsoft recorded compauth=fail reason=000, meaning explicit authentication failed: DMARC failed and the policy is quarantine or reject.

Policy, plain: The sender's DMARC setting says to refuse fake mail. Microsoft kept the message but treated it as suspicious instead.

Policy, technical: Microsoft recorded action=oreject: the domain's policy is reject and Microsoft overrode it. Microsoft's own pages disagree on whether that means junk or quarantine, so the page does not say which. The message was not refused outright.

Delivery, plain: shop.example's DMARC setting asks mail providers to refuse mail that fails this way. Expect the ones that follow it to refuse every message with this problem.

Delivery, technical: Microsoft's action=oreject shows that shop.example publishes a reject policy, which asks receivers to reject mail that fails DMARC (RFC 9989 4.7). Every message that fails this way falls under it. A receiver is not required to honor the request, so some copies may still arrive.

Fix 1, plain: Turn on email signing (DKIM) for shop.example in the settings of the service that sends this mail. It adds a digital signature with your domain to every message, and that signature still works when mail is forwarded.

Fix 1, technical: Turn on DKIM signing for shop.example at the sending service. Aligned DKIM lets DMARC pass, including after a forward.

Fix 2, plain: If you sent this, ask whoever manages the DNS for shop.example to add the service that sends this mail to its list of allowed servers (the SPF record). The service's setup page gives the exact entry. If you didn't send it, someone else used your domain and the check correctly failed it.

Fix 2, technical: If this is your mail, add the sending service to the SPF record of shop.example. If it is not, the SPF failure is correct.

Limit 1, plain: This page assumes the usual, looser domain match. A domain's DMARC setting can demand an exact match, and the headers don't show that setting.

Limit 1, technical: Alignment is computed in relaxed mode, the DMARC default, with strict mode beside it. adkim and aspf are set in the DMARC record, which is not in the headers.

Sender signals, plain: Maybe not. Treat this message with care.

Sender signals, technical: One signal says the author may not be who the From line shows.

Sender signal 1, plain: This message failed the sender check (DMARC), so nothing proves it came from shop.example.

Sender signal 1, technical: DMARC failed for the From domain shop.example (RFC5322.From), so no aligned SPF or DKIM pass vouches for the author domain.

Spam signals, plain: These headers can't say. They carry no spam rating from the receiving system that this page can read.

Spam signals, technical: No spam filter result that this page can read was written by the receiver.

## Microsoft action quarantine

Plain headline: This message failed the sender check (DMARC). The signature didn't check out and the sending server isn't on the sender's list of approved servers. Nothing proved it came from shop.example.

Technical headline: DMARC at Microsoft 365 failed because DKIM d=shop.example failed verification and SPF soft failed for the Return-Path domain shop.example (RFC5321.MailFrom), so no identifier passed for the From domain shop.example (RFC5322.From).

Cause, plain: The message was changed after it was signed, or the signature doesn't match the sender's published key. Microsoft's own sender check failed it too.

Cause, technical: The DKIM signature from shop.example did not verify at Microsoft 365 (body hash did not verify): something changed the signed part of the message after signing, or the key in DNS does not match. The SPF record of shop.example does not authorize the server that handed the message over and asks receivers to treat it as suspicious rather than fail it outright (softfail), as Microsoft 365 reported. Microsoft recorded compauth=fail reason=000, meaning explicit authentication failed: DMARC failed and the policy is quarantine or reject.

Policy, plain: Microsoft put the message in junk or quarantine because of the sender's DMARC setting.

Policy, technical: Microsoft recorded action=quarantine: the policy sent this message to junk or quarantine.

Delivery, plain: shop.example's DMARC setting asks mail providers to send mail that fails this way to spam. Expect that for every message with this problem, at the ones that follow it.

Delivery, technical: Microsoft's action=quarantine shows that shop.example publishes a quarantine policy, which asks receivers to treat mail that fails DMARC as suspicious (RFC 9989 4.7). Every message that fails this way falls under it. A receiver is not required to honor the request.

Detail 1, plain: The signature from shop.example didn't check out.

Detail 1, technical: DKIM failed for d=shop.example (body hash did not verify). Something changed the signed headers or body after signing, or the key in DNS does not match; the headers cannot show which.

Detail 2, plain: shop.example's list of approved servers doesn't include the server that sent this, and asks receivers to treat that as suspicious rather than refuse it.

Detail 2, technical: SPF soft failed for shop.example (sender IP is 198.51.100.44).

Fix 1, plain: Ask whoever manages your mail whether anything adds a footer, a disclaimer, or tracking links after messages leave the service that sends this mail. That's the usual cause of a broken signature.

Fix 1, technical: The signature from d=shop.example broke between signing and Microsoft 365. Look for anything that edits mail after the sending service signs it (a gateway, footer, disclaimer, or link rewriting), and check that the key at <selector>._domainkey.shop.example is the one it signs with.

Fix 2, plain: If you sent this, ask whoever manages the DNS for shop.example to add the service that sends this mail to its list of allowed servers (the SPF record). The service's setup page gives the exact entry. If you didn't send it, someone else used your domain and the check correctly failed it.

Fix 2, technical: If this is your mail, add the sending service to the SPF record of shop.example. If it is not, the SPF failure is correct.

Limit 1, plain: This page assumes the usual, looser domain match. A domain's DMARC setting can demand an exact match, and the headers don't show that setting.

Limit 1, technical: Alignment is computed in relaxed mode, the DMARC default, with strict mode beside it. adkim and aspf are set in the DMARC record, which is not in the headers.

Sender signals, plain: Maybe not. Treat this message with care.

Sender signals, technical: One signal says the author may not be who the From line shows.

Sender signal 1, plain: This message failed the sender check (DMARC), so nothing proves it came from shop.example.

Sender signal 1, technical: DMARC failed for the From domain shop.example (RFC5322.From), so no aligned SPF or DKIM pass vouches for the author domain.

Spam signals, plain: These headers can't say. They carry no spam rating from the receiving system that this page can read.

Spam signals, technical: No spam filter result that this page can read was written by the receiver.

## Microsoft action none

Plain headline: This message failed the sender check (DMARC). It was signed by mailer.example and it came from a server that bounce.mailer.example allows. Neither of those is shop.example, the domain in the From address.

Technical headline: DMARC at Microsoft 365 failed because DKIM d=mailer.example passed and SPF passed for the Return-Path domain bounce.mailer.example (RFC5321.MailFrom), but neither aligns with the From domain shop.example (RFC5322.From).

Cause, plain: The service sending this mail is using its own domain instead of shop.example, so the checks pass for the service but not for the sender. Microsoft's own sender check failed it too.

Cause, technical: The checks passed, but for mailer.example and bounce.mailer.example, domains that are not shop.example. That is what happens when the sending service's own domain signs and bounces the mail. DMARC counts a pass only on the From domain or, in relaxed mode, its organizational domain. Microsoft recorded compauth=fail reason=001, meaning implicit authentication failed: no authentication records, or only weak ones (SPF ~all or ?all, DMARC p=none).

Policy, plain: Microsoft took no action over the failure, so it didn't send the message to junk for this reason.

Policy, technical: Microsoft recorded action=none: it applied no DMARC action to this message.

Delivery, plain: Gmail, Yahoo, and Microsoft's Outlook.com require bulk senders to pass the sender check (DMARC), and mail with this problem doesn't. Gmail and Outlook.com count bulk as 5,000 messages a day, and may refuse mail that falls short or send it to spam.

Delivery, technical: Bulk senders must pass DMARC with SPF or DKIM aligned, and nothing that passes here aligns with shop.example. Google's Email sender guidelines, Yahoo's Sender Best Practices, and Microsoft's Outlook.com requirements for high volume senders all say so. Google and Microsoft draw the line at 5,000 messages a day, and mail that falls short may be rejected or marked as spam.

Detail 1, plain: The message was signed, but by mailer.example, not by the sender's own domain.

Detail 1, technical: DKIM passed for d=mailer.example, which does not align with shop.example. A pass on another domain does not count for DMARC.

Detail 2, plain: The sending server is approved, but by bounce.mailer.example, not by the sender's own domain.

Detail 2, technical: SPF passed for bounce.mailer.example, which does not align with shop.example. A pass on another domain does not count for DMARC.

Fix 1, plain: In the settings of the service that sends this mail, turn on domain authentication for shop.example. The service gives you a few DNS records to add, and after that your mail is signed with your own domain instead of mailer.example.

Fix 1, technical: At the sending service, set up domain authentication for shop.example so the DKIM signature carries d=shop.example or a subdomain of it, instead of d=mailer.example.

Fix 2, plain: Once the signature is fixed, you can also give the service that sends this mail a custom return address on shop.example. Services call it a custom return path or sending domain. It's optional.

Fix 2, technical: Second, after DKIM: set a custom Return-Path (bounce) domain under shop.example at the sending service so SPF aligns too.

Limit 1, plain: This page assumes the usual, looser domain match. A domain's DMARC setting can demand an exact match, and the headers don't show that setting.

Limit 1, technical: Alignment is computed in relaxed mode, the DMARC default, with strict mode beside it. adkim and aspf are set in the DMARC record, which is not in the headers.

Sender signals, plain: Maybe not. Treat this message with care.

Sender signals, technical: One signal says the author may not be who the From line shows.

Sender signal 1, plain: This message failed the sender check (DMARC), so nothing proves it came from shop.example.

Sender signal 1, technical: DMARC failed for the From domain shop.example (RFC5322.From), so no aligned SPF or DKIM pass vouches for the author domain.

Spam signals, plain: These headers can't say. They carry no spam rating from the receiving system that this page can read.

Spam signals, technical: No spam filter result that this page can read was written by the receiver.

## compauth 0xx, explicit fail

Plain headline: This message failed the sender check (DMARC). It carried no signature and the sending server isn't on the sender's list of approved servers. Nothing proved it came from shop.example.

Technical headline: DMARC at Microsoft 365 failed because there was no DKIM signature and SPF failed for the Return-Path domain shop.example (RFC5321.MailFrom), so no identifier passed for the From domain shop.example (RFC5322.From).

Cause, plain: The server that sent this isn't on the sender's list of approved servers (SPF). Microsoft's own sender check failed it too.

Cause, technical: There is no DKIM signature, so DMARC depends on SPF alone. The server that handed the message over is not authorized by the SPF record of shop.example, as Microsoft 365 reported. Microsoft recorded compauth=fail reason=002, meaning the organization prohibits this sender and domain pair from sending spoofed mail.

Policy, plain: Microsoft refused the message because of the sender's DMARC setting.

Policy, technical: Microsoft recorded action=reject.

Delivery, plain: shop.example's DMARC setting asks mail providers to refuse mail that fails this way. Expect the ones that follow it to refuse every message with this problem.

Delivery, technical: Microsoft's action=reject shows that shop.example publishes a reject policy, which asks receivers to reject mail that fails DMARC (RFC 9989 4.7). Every message that fails this way falls under it. A receiver is not required to honor the request, so some copies may still arrive.

Fix 1, plain: Turn on email signing (DKIM) for shop.example in the settings of the service that sends this mail. It adds a digital signature with your domain to every message, and that signature still works when mail is forwarded.

Fix 1, technical: Turn on DKIM signing for shop.example at the sending service. Aligned DKIM lets DMARC pass, including after a forward.

Fix 2, plain: If you sent this, ask whoever manages the DNS for shop.example to add the service that sends this mail to its list of allowed servers (the SPF record). The service's setup page gives the exact entry. If you didn't send it, someone else used your domain and the check correctly failed it.

Fix 2, technical: If this is your mail, add the sending service to the SPF record of shop.example. If it is not, the SPF failure is correct.

Limit 1, plain: This page assumes the usual, looser domain match. A domain's DMARC setting can demand an exact match, and the headers don't show that setting.

Limit 1, technical: Alignment is computed in relaxed mode, the DMARC default, with strict mode beside it. adkim and aspf are set in the DMARC record, which is not in the headers.

Sender signals, plain: Maybe not. Treat this message with care.

Sender signals, technical: One signal says the author may not be who the From line shows.

Sender signal 1, plain: This message failed the sender check (DMARC), so nothing proves it came from shop.example.

Sender signal 1, technical: DMARC failed for the From domain shop.example (RFC5322.From), so no aligned SPF or DKIM pass vouches for the author domain.

Spam signals, plain: These headers can't say. They carry no spam rating from the receiving system that this page can read.

Spam signals, technical: No spam filter result that this page can read was written by the receiver.

## compauth 1xx, pass

Plain headline: This message passed the sender check (DMARC). It was signed by shop.example, the domain in the From address, and came from a server it allows.

Technical headline: DMARC at Microsoft 365 passed because DKIM d=shop.example passed and SPF passed for the Return-Path domain shop.example (RFC5321.MailFrom), and both align with the From domain shop.example (RFC5322.From).

Cause, plain: A message passes when it's signed by, or sent for, the domain in its From address, and this one was. Microsoft's own sender check still passed it.

Cause, technical: For shop.example, both SPF and DKIM pass and align, so the message still passes after a forward that breaks SPF. Microsoft recorded compauth=pass reason=100, meaning SPF or DKIM passed and aligns with the From domain.

Policy, plain: The message passed, so the sender's DMARC setting didn't come into play.

Policy, technical: Microsoft recorded action=none; the message passed, so no action was needed.

Delivery, plain: Mail sent this way meets the rules Gmail, Yahoo, and Microsoft's Outlook.com set for proving who sent a message. Those rules also cover spam complaints and unsubscribe links, which the headers don't show.

Delivery, technical: SPF and DKIM both pass, and both align with the From domain shop.example, which publishes a DMARC record. That meets the authentication requirements for bulk senders. Google's Email sender guidelines, Yahoo's Sender Best Practices, and Microsoft's Outlook.com requirements for high volume senders all say so. Their spam rate and unsubscribe requirements are outside the headers.

Detail 1, plain: The message was signed by shop.example, which belongs to the sender.

Detail 1, technical: DKIM passed for d=shop.example, which aligns with shop.example.

Detail 2, plain: The sending server is approved by shop.example, which belongs to the sender.

Detail 2, technical: SPF passed for shop.example, which aligns with shop.example.

Limit 1, plain: This page assumes the usual, looser domain match. A domain's DMARC setting can demand an exact match, and the headers don't show that setting.

Limit 1, technical: Alignment is computed in relaxed mode, the DMARC default, with strict mode beside it. adkim and aspf are set in the DMARC record, which is not in the headers.

Sender signals, plain: Yes, as far as the headers show.

Sender signals, technical: No flag fired: DMARC passed for shop.example, and the display name, Reply-To, and From domain raise nothing.

Spam signals, plain: These headers can't say. They carry no spam rating from the receiving system that this page can read.

Spam signals, technical: No spam filter result that this page can read was written by the receiver.

Signals, nothing fired, plain: Nothing in the headers points to forgery or spam. That covers the headers only, because this page doesn't judge the message text, links, or attachments.

Signals, nothing fired, technical: Nothing in the headers points to forgery or spam. That is a statement about the headers only: the body, links and attachments are not examined.

## compauth 2xx, soft pass

Plain headline: shop.example has no DMARC setting, so the sender check didn't apply. With one, this message would fail.

Technical headline: DMARC did not apply because Microsoft 365 found no DMARC record for shop.example; with one, this message would fail.

Cause, plain: Without a DMARC setting, nothing stops others from sending mail that claims to be from shop.example. This message wouldn't pass if one were added. Microsoft's own sender check gave it a soft pass.

Cause, technical: Without a DMARC record nothing ties SPF and DKIM to the From domain, so a receiver judges the message on its own signals, and anyone can put shop.example in a From address without failing a policy. With a record this message would fail, because there was no DKIM signature and SPF failed for the Return-Path domain shop.example (RFC5321.MailFrom), so no identifier passed for the From domain shop.example (RFC5322.From). Microsoft recorded compauth=softpass reason=201, meaning the PTR of the From domain aligns with the subnet of the connecting IP's PTR.

Policy, plain: shop.example has no DMARC setting, so it gives mail providers no instructions for fake mail. Each provider decides for itself.

Policy, technical: shop.example publishes no DMARC policy, so nothing tells receivers what to do with mail that fails. Each receiver decides on its own.

Delivery, plain: Gmail, Yahoo, and Microsoft's Outlook.com require a DMARC setting from anyone who sends them mail in bulk. Gmail and Outlook.com count bulk as 5,000 messages a day, and may refuse mail that falls short or send it to spam.

Delivery, technical: Bulk senders must publish a DMARC record, at least p=none. Google's Email sender guidelines, Yahoo's Sender Best Practices, and Microsoft's Outlook.com requirements for high volume senders all say so. Google and Microsoft draw the line at 5,000 messages a day, and mail that falls short may be rejected or marked as spam.

Detail 1, plain: shop.example's list of approved servers doesn't include the server that sent this.

Detail 1, technical: SPF failed for shop.example (sender IP is 198.51.100.44).

Fix 1, plain: Ask whoever manages the DNS for shop.example to add a DMARC record. Start with the setting that only sends reports, and tighten it once the reports show all your real mail passes.

Fix 1, technical: Publish a DMARC record at _dmarc.shop.example with p=none and a rua= address, read the reports, then move to p=quarantine once every real source passes.

Fix 2, plain: Turn on email signing (DKIM) for shop.example in the settings of the service that sends this mail. It adds a digital signature with your domain to every message, and that signature still works when mail is forwarded.

Fix 2, technical: Turn on DKIM signing for shop.example at the sending service. Aligned DKIM lets DMARC pass, including after a forward.

Fix 3, plain: If you sent this, ask whoever manages the DNS for shop.example to add the service that sends this mail to its list of allowed servers (the SPF record). The service's setup page gives the exact entry. If you didn't send it, someone else used your domain and the check correctly failed it.

Fix 3, technical: If this is your mail, add the sending service to the SPF record of shop.example. If it is not, the SPF failure is correct.

Limit 1, plain: This page assumes the usual, looser domain match. A domain's DMARC setting can demand an exact match, and the headers don't show that setting.

Limit 1, technical: Alignment is computed in relaxed mode, the DMARC default, with strict mode beside it. adkim and aspf are set in the DMARC record, which is not in the headers.

Sender signals, plain: There's a reason to look twice.

Sender signals, technical: One signal says the author may not be who the From line shows.

Sender signal 1, plain: shop.example has no DMARC setting, so the headers can't prove the message came from shop.example.

Sender signal 1, technical: shop.example publishes no DMARC record, so no receiver is told to tie SPF or DKIM to the From domain.

Spam signals, plain: These headers can't say. They carry no spam rating from the receiving system that this page can read.

Spam signals, technical: No spam filter result that this page can read was written by the receiver.

## compauth 3xx, not checked

Plain headline: shop.example has no DMARC setting, so the sender check didn't apply. With one, this message would fail.

Technical headline: DMARC did not apply because Microsoft 365 found no DMARC record for shop.example; with one, this message would fail.

Cause, plain: Without a DMARC setting, nothing stops others from sending mail that claims to be from shop.example. This message wouldn't pass if one were added.

Cause, technical: Without a DMARC record nothing ties SPF and DKIM to the From domain, so a receiver judges the message on its own signals, and anyone can put shop.example in a From address without failing a policy. With a record this message would fail, because there was no DKIM signature and SPF failed for the Return-Path domain shop.example (RFC5321.MailFrom), so no identifier passed for the From domain shop.example (RFC5322.From). Microsoft recorded compauth=none reason=300, meaning not checked for composite authentication (code 300 has no entry of its own).

Policy, plain: shop.example has no DMARC setting, so it gives mail providers no instructions for fake mail. Each provider decides for itself.

Policy, technical: shop.example publishes no DMARC policy, so nothing tells receivers what to do with mail that fails. Each receiver decides on its own.

Delivery, plain: Gmail, Yahoo, and Microsoft's Outlook.com require a DMARC setting from anyone who sends them mail in bulk. Gmail and Outlook.com count bulk as 5,000 messages a day, and may refuse mail that falls short or send it to spam.

Delivery, technical: Bulk senders must publish a DMARC record, at least p=none. Google's Email sender guidelines, Yahoo's Sender Best Practices, and Microsoft's Outlook.com requirements for high volume senders all say so. Google and Microsoft draw the line at 5,000 messages a day, and mail that falls short may be rejected or marked as spam.

Detail 1, plain: shop.example's list of approved servers doesn't include the server that sent this.

Detail 1, technical: SPF failed for shop.example (sender IP is 198.51.100.44).

Fix 1, plain: Ask whoever manages the DNS for shop.example to add a DMARC record. Start with the setting that only sends reports, and tighten it once the reports show all your real mail passes.

Fix 1, technical: Publish a DMARC record at _dmarc.shop.example with p=none and a rua= address, read the reports, then move to p=quarantine once every real source passes.

Fix 2, plain: Turn on email signing (DKIM) for shop.example in the settings of the service that sends this mail. It adds a digital signature with your domain to every message, and that signature still works when mail is forwarded.

Fix 2, technical: Turn on DKIM signing for shop.example at the sending service. Aligned DKIM lets DMARC pass, including after a forward.

Fix 3, plain: If you sent this, ask whoever manages the DNS for shop.example to add the service that sends this mail to its list of allowed servers (the SPF record). The service's setup page gives the exact entry. If you didn't send it, someone else used your domain and the check correctly failed it.

Fix 3, technical: If this is your mail, add the sending service to the SPF record of shop.example. If it is not, the SPF failure is correct.

Limit 1, plain: This page assumes the usual, looser domain match. A domain's DMARC setting can demand an exact match, and the headers don't show that setting.

Limit 1, technical: Alignment is computed in relaxed mode, the DMARC default, with strict mode beside it. adkim and aspf are set in the DMARC record, which is not in the headers.

Sender signals, plain: There's a reason to look twice.

Sender signals, technical: One signal says the author may not be who the From line shows.

Sender signal 1, plain: shop.example has no DMARC setting, so the headers can't prove the message came from shop.example.

Sender signal 1, technical: shop.example publishes no DMARC record, so no receiver is told to tie SPF or DKIM to the From domain.

Spam signals, plain: These headers can't say. They carry no spam rating from the receiving system that this page can read.

Spam signals, technical: No spam filter result that this page can read was written by the receiver.

## compauth 4xx, bypassed

Plain headline: This message failed the sender check (DMARC). It carried no signature and the sending server isn't on the sender's list of approved servers. Nothing proved it came from shop.example.

Technical headline: DMARC at Microsoft 365 failed because there was no DKIM signature and SPF failed for the Return-Path domain shop.example (RFC5321.MailFrom), so no identifier passed for the From domain shop.example (RFC5322.From).

Cause, plain: The server that sent this isn't on the sender's list of approved servers (SPF).

Cause, technical: There is no DKIM signature, so DMARC depends on SPF alone. The server that handed the message over is not authorized by the SPF record of shop.example, as Microsoft 365 reported. Microsoft recorded compauth=none reason=451, meaning bypassed composite authentication (code 451 has no entry of its own).

Policy, plain: Microsoft took no action over the failure, so it didn't send the message to junk for this reason.

Policy, technical: Microsoft recorded action=none: it applied no DMARC action to this message.

Delivery, plain: Gmail and Yahoo expect all mail to carry a valid digital signature or to come from a server the domain allows. This message did neither, and Gmail says it may refuse such mail or send it to spam.

Delivery, technical: This message passed neither SPF nor DKIM. Google and Yahoo require one of them from every sender. Google says such mail might be marked as spam or rejected with a 5.7.26 error.

Fix 1, plain: Turn on email signing (DKIM) for shop.example in the settings of the service that sends this mail. It adds a digital signature with your domain to every message, and that signature still works when mail is forwarded.

Fix 1, technical: Turn on DKIM signing for shop.example at the sending service. Aligned DKIM lets DMARC pass, including after a forward.

Fix 2, plain: If you sent this, ask whoever manages the DNS for shop.example to add the service that sends this mail to its list of allowed servers (the SPF record). The service's setup page gives the exact entry. If you didn't send it, someone else used your domain and the check correctly failed it.

Fix 2, technical: If this is your mail, add the sending service to the SPF record of shop.example. If it is not, the SPF failure is correct.

Limit 1, plain: This page assumes the usual, looser domain match. A domain's DMARC setting can demand an exact match, and the headers don't show that setting.

Limit 1, technical: Alignment is computed in relaxed mode, the DMARC default, with strict mode beside it. adkim and aspf are set in the DMARC record, which is not in the headers.

Sender signals, plain: Maybe not. Treat this message with care.

Sender signals, technical: One signal says the author may not be who the From line shows.

Sender signal 1, plain: This message failed the sender check (DMARC), so nothing proves it came from shop.example.

Sender signal 1, technical: DMARC failed for the From domain shop.example (RFC5322.From), so no aligned SPF or DKIM pass vouches for the author domain.

Spam signals, plain: These headers can't say. They carry no spam rating from the receiving system that this page can read.

Spam signals, technical: No spam filter result that this page can read was written by the receiver.

## compauth 5xx, bounce not enforced

Plain headline: This message failed the sender check (DMARC). It carried no signature and the sending server isn't on the sender's list of approved servers. Nothing proved it came from shop.example.

Technical headline: DMARC at Microsoft 365 failed because there was no DKIM signature and SPF failed for the Return-Path domain shop.example (RFC5321.MailFrom), so no identifier passed for the From domain shop.example (RFC5322.From).

Cause, plain: The server that sent this isn't on the sender's list of approved servers (SPF). Microsoft's own sender check still passed it.

Cause, technical: There is no DKIM signature, so DMARC depends on SPF alone. The server that handed the message over is not authorized by the SPF record of shop.example, as Microsoft 365 reported. Microsoft recorded compauth=pass reason=501, meaning DMARC not enforced: a valid bounce where sender and recipient had prior contact.

Policy, plain: Microsoft took no action over the failure, so it didn't send the message to junk for this reason.

Policy, technical: Microsoft recorded action=none: it applied no DMARC action to this message.

Delivery, plain: Gmail and Yahoo expect all mail to carry a valid digital signature or to come from a server the domain allows. This message did neither, and Gmail says it may refuse such mail or send it to spam.

Delivery, technical: This message passed neither SPF nor DKIM. Google and Yahoo require one of them from every sender. Google says such mail might be marked as spam or rejected with a 5.7.26 error.

Fix 1, plain: Turn on email signing (DKIM) for shop.example in the settings of the service that sends this mail. It adds a digital signature with your domain to every message, and that signature still works when mail is forwarded.

Fix 1, technical: Turn on DKIM signing for shop.example at the sending service. Aligned DKIM lets DMARC pass, including after a forward.

Fix 2, plain: If you sent this, ask whoever manages the DNS for shop.example to add the service that sends this mail to its list of allowed servers (the SPF record). The service's setup page gives the exact entry. If you didn't send it, someone else used your domain and the check correctly failed it.

Fix 2, technical: If this is your mail, add the sending service to the SPF record of shop.example. If it is not, the SPF failure is correct.

Limit 1, plain: This page assumes the usual, looser domain match. A domain's DMARC setting can demand an exact match, and the headers don't show that setting.

Limit 1, technical: Alignment is computed in relaxed mode, the DMARC default, with strict mode beside it. adkim and aspf are set in the DMARC record, which is not in the headers.

Sender signals, plain: Maybe not. Treat this message with care.

Sender signals, technical: One signal says the author may not be who the From line shows.

Sender signal 1, plain: This message failed the sender check (DMARC), so nothing proves it came from shop.example.

Sender signal 1, technical: DMARC failed for the From domain shop.example (RFC5322.From), so no aligned SPF or DKIM pass vouches for the author domain.

Spam signals, plain: These headers can't say. They carry no spam rating from the receiving system that this page can read.

Spam signals, technical: No spam filter result that this page can read was written by the receiver.

## compauth 6xx, implicit fail

Plain headline: This message failed the sender check (DMARC). It carried no signature and the sending server isn't on the sender's list of approved servers. Nothing proved it came from shop.example.

Technical headline: DMARC at Microsoft 365 failed because there was no DKIM signature and SPF failed for the Return-Path domain shop.example (RFC5321.MailFrom), so no identifier passed for the From domain shop.example (RFC5322.From).

Cause, plain: The server that sent this isn't on the sender's list of approved servers (SPF). Microsoft's own sender check failed it too.

Cause, technical: There is no DKIM signature, so DMARC depends on SPF alone. The server that handed the message over is not authorized by the SPF record of shop.example, as Microsoft 365 reported. Microsoft recorded compauth=fail reason=601, meaning the From domain is one of the organization's accepted domains (self-to-self or intra-org spoofing).

Policy, plain: Microsoft put the message in junk or quarantine because of the sender's DMARC setting.

Policy, technical: Microsoft recorded action=quarantine: the policy sent this message to junk or quarantine.

Delivery, plain: shop.example's DMARC setting asks mail providers to send mail that fails this way to spam. Expect that for every message with this problem, at the ones that follow it.

Delivery, technical: Microsoft's action=quarantine shows that shop.example publishes a quarantine policy, which asks receivers to treat mail that fails DMARC as suspicious (RFC 9989 4.7). Every message that fails this way falls under it. A receiver is not required to honor the request.

Fix 1, plain: Turn on email signing (DKIM) for shop.example in the settings of the service that sends this mail. It adds a digital signature with your domain to every message, and that signature still works when mail is forwarded.

Fix 1, technical: Turn on DKIM signing for shop.example at the sending service. Aligned DKIM lets DMARC pass, including after a forward.

Fix 2, plain: If you sent this, ask whoever manages the DNS for shop.example to add the service that sends this mail to its list of allowed servers (the SPF record). The service's setup page gives the exact entry. If you didn't send it, someone else used your domain and the check correctly failed it.

Fix 2, technical: If this is your mail, add the sending service to the SPF record of shop.example. If it is not, the SPF failure is correct.

Limit 1, plain: This page assumes the usual, looser domain match. A domain's DMARC setting can demand an exact match, and the headers don't show that setting.

Limit 1, technical: Alignment is computed in relaxed mode, the DMARC default, with strict mode beside it. adkim and aspf are set in the DMARC record, which is not in the headers.

Sender signals, plain: Maybe not. Treat this message with care.

Sender signals, technical: One signal says the author may not be who the From line shows.

Sender signal 1, plain: This message failed the sender check (DMARC), so nothing proves it came from shop.example.

Sender signal 1, technical: DMARC failed for the From domain shop.example (RFC5322.From), so no aligned SPF or DKIM pass vouches for the author domain.

Spam signals, plain: These headers can't say. They carry no spam rating from the receiving system that this page can read.

Spam signals, technical: No spam filter result that this page can read was written by the receiver.

## compauth 7xx, history pass

Plain headline: This message failed the sender check (DMARC). It carried no signature and the sending server isn't on the sender's list of approved servers. Nothing proved it came from shop.example.

Technical headline: DMARC at Microsoft 365 failed because there was no DKIM signature and SPF failed for the Return-Path domain shop.example (RFC5321.MailFrom), so no identifier passed for the From domain shop.example (RFC5322.From).

Cause, plain: The server that sent this isn't on the sender's list of approved servers (SPF). Microsoft's own sender check still passed it.

Cause, technical: There is no DKIM signature, so DMARC depends on SPF alone. The server that handed the message over is not authorized by the SPF record of shop.example, as Microsoft 365 reported. Microsoft recorded compauth=pass reason=701, meaning DMARC not enforced because the organization has a history of legitimate mail from this infrastructure.

Policy, plain: Microsoft took no action over the failure, so it didn't send the message to junk for this reason.

Policy, technical: Microsoft recorded action=none: it applied no DMARC action to this message.

Delivery, plain: Gmail and Yahoo expect all mail to carry a valid digital signature or to come from a server the domain allows. This message did neither, and Gmail says it may refuse such mail or send it to spam.

Delivery, technical: This message passed neither SPF nor DKIM. Google and Yahoo require one of them from every sender. Google says such mail might be marked as spam or rejected with a 5.7.26 error.

Fix 1, plain: Turn on email signing (DKIM) for shop.example in the settings of the service that sends this mail. It adds a digital signature with your domain to every message, and that signature still works when mail is forwarded.

Fix 1, technical: Turn on DKIM signing for shop.example at the sending service. Aligned DKIM lets DMARC pass, including after a forward.

Fix 2, plain: If you sent this, ask whoever manages the DNS for shop.example to add the service that sends this mail to its list of allowed servers (the SPF record). The service's setup page gives the exact entry. If you didn't send it, someone else used your domain and the check correctly failed it.

Fix 2, technical: If this is your mail, add the sending service to the SPF record of shop.example. If it is not, the SPF failure is correct.

Limit 1, plain: This page assumes the usual, looser domain match. A domain's DMARC setting can demand an exact match, and the headers don't show that setting.

Limit 1, technical: Alignment is computed in relaxed mode, the DMARC default, with strict mode beside it. adkim and aspf are set in the DMARC record, which is not in the headers.

Sender signals, plain: Maybe not. Treat this message with care.

Sender signals, technical: One signal says the author may not be who the From line shows.

Sender signal 1, plain: This message failed the sender check (DMARC), so nothing proves it came from shop.example.

Sender signal 1, technical: DMARC failed for the From domain shop.example (RFC5322.From), so no aligned SPF or DKIM pass vouches for the author domain.

Spam signals, plain: These headers can't say. They carry no spam rating from the receiving system that this page can read.

Spam signals, technical: No spam filter result that this page can read was written by the receiver.

## compauth 8xx, not in the table

Plain headline: This message failed the sender check (DMARC). It carried no signature and the sending server isn't on the sender's list of approved servers. Nothing proved it came from shop.example.

Technical headline: DMARC at Microsoft 365 failed because there was no DKIM signature and SPF failed for the Return-Path domain shop.example (RFC5321.MailFrom), so no identifier passed for the From domain shop.example (RFC5322.From).

Cause, plain: The server that sent this isn't on the sender's list of approved servers (SPF). Microsoft's own sender check failed it too.

Cause, technical: There is no DKIM signature, so DMARC depends on SPF alone. The server that handed the message over is not authorized by the SPF record of shop.example, as Microsoft 365 reported. Microsoft recorded compauth=fail reason=801, a code not in its published table.

Policy, plain: Microsoft put the message in junk or quarantine because of the sender's DMARC setting.

Policy, technical: Microsoft recorded action=quarantine: the policy sent this message to junk or quarantine.

Delivery, plain: shop.example's DMARC setting asks mail providers to send mail that fails this way to spam. Expect that for every message with this problem, at the ones that follow it.

Delivery, technical: Microsoft's action=quarantine shows that shop.example publishes a quarantine policy, which asks receivers to treat mail that fails DMARC as suspicious (RFC 9989 4.7). Every message that fails this way falls under it. A receiver is not required to honor the request.

Fix 1, plain: Turn on email signing (DKIM) for shop.example in the settings of the service that sends this mail. It adds a digital signature with your domain to every message, and that signature still works when mail is forwarded.

Fix 1, technical: Turn on DKIM signing for shop.example at the sending service. Aligned DKIM lets DMARC pass, including after a forward.

Fix 2, plain: If you sent this, ask whoever manages the DNS for shop.example to add the service that sends this mail to its list of allowed servers (the SPF record). The service's setup page gives the exact entry. If you didn't send it, someone else used your domain and the check correctly failed it.

Fix 2, technical: If this is your mail, add the sending service to the SPF record of shop.example. If it is not, the SPF failure is correct.

Limit 1, plain: This page assumes the usual, looser domain match. A domain's DMARC setting can demand an exact match, and the headers don't show that setting.

Limit 1, technical: Alignment is computed in relaxed mode, the DMARC default, with strict mode beside it. adkim and aspf are set in the DMARC record, which is not in the headers.

Sender signals, plain: Maybe not. Treat this message with care.

Sender signals, technical: One signal says the author may not be who the From line shows.

Sender signal 1, plain: This message failed the sender check (DMARC), so nothing proves it came from shop.example.

Sender signal 1, technical: DMARC failed for the From domain shop.example (RFC5322.From), so no aligned SPF or DKIM pass vouches for the author domain.

Spam signals, plain: These headers can't say. They carry no spam rating from the receiving system that this page can read.

Spam signals, technical: No spam filter result that this page can read was written by the receiver.

## compauth 9xx, complex routing

Plain headline: This message failed the sender check (DMARC). It carried no signature and the sending server isn't on the sender's list of approved servers. Nothing proved it came from shop.example.

Technical headline: DMARC at Microsoft 365 failed because there was no DKIM signature and SPF failed for the Return-Path domain shop.example (RFC5321.MailFrom), so no identifier passed for the From domain shop.example (RFC5322.From).

Cause, plain: The server that sent this isn't on the sender's list of approved servers (SPF).

Cause, technical: There is no DKIM signature, so DMARC depends on SPF alone. The server that handed the message over is not authorized by the SPF record of shop.example, as Microsoft 365 reported. Microsoft recorded compauth=none reason=905, meaning DMARC not enforced because of complex routing, such as mail through on-premises Exchange or another service first.

Policy, plain: Microsoft took no action over the failure, so it didn't send the message to junk for this reason.

Policy, technical: Microsoft recorded action=none: it applied no DMARC action to this message.

Delivery, plain: Gmail and Yahoo expect all mail to carry a valid digital signature or to come from a server the domain allows. This message did neither, and Gmail says it may refuse such mail or send it to spam.

Delivery, technical: This message passed neither SPF nor DKIM. Google and Yahoo require one of them from every sender. Google says such mail might be marked as spam or rejected with a 5.7.26 error.

Fix 1, plain: Turn on email signing (DKIM) for shop.example in the settings of the service that sends this mail. It adds a digital signature with your domain to every message, and that signature still works when mail is forwarded.

Fix 1, technical: Turn on DKIM signing for shop.example at the sending service. Aligned DKIM lets DMARC pass, including after a forward.

Fix 2, plain: If you sent this, ask whoever manages the DNS for shop.example to add the service that sends this mail to its list of allowed servers (the SPF record). The service's setup page gives the exact entry. If you didn't send it, someone else used your domain and the check correctly failed it.

Fix 2, technical: If this is your mail, add the sending service to the SPF record of shop.example. If it is not, the SPF failure is correct.

Limit 1, plain: This page assumes the usual, looser domain match. A domain's DMARC setting can demand an exact match, and the headers don't show that setting.

Limit 1, technical: Alignment is computed in relaxed mode, the DMARC default, with strict mode beside it. adkim and aspf are set in the DMARC record, which is not in the headers.

Sender signals, plain: Maybe not. Treat this message with care.

Sender signals, technical: One signal says the author may not be who the From line shows.

Sender signal 1, plain: This message failed the sender check (DMARC), so nothing proves it came from shop.example.

Sender signal 1, technical: DMARC failed for the From domain shop.example (RFC5322.From), so no aligned SPF or DKIM pass vouches for the author domain.

Spam signals, plain: These headers can't say. They carry no spam rating from the receiving system that this page can read.

Spam signals, technical: No spam filter result that this page can read was written by the receiver.

## pass by SPF for the HELO identity, null Return-Path

Plain headline: This message passed the sender check (DMARC). The sending server called itself o1.shop.example, and o1.shop.example allows it. That belongs to shop.example, the domain in the From address, or to its parent domain.

Technical headline: DMARC at mx.receiver.example passed because SPF passed for the HELO identity o1.shop.example, and it aligns with the From domain shop.example (RFC5322.From) under relaxed alignment, through the organizational domain.

Cause, plain: A message passes when it's signed by, or sent for, the domain in its From address, and this one was.

Cause, technical: For shop.example, only SPF passes and aligns. A forward or a mailing list breaks it, because SPF checks whichever server hands the message over; aligned DKIM would still pass.

Policy, plain: The message passed, so the sender's DMARC setting didn't come into play.

Policy, technical: shop.example publishes p=reject, which asks for failing mail to be refused. This message passed, so the policy did not come into play.

Delivery, plain: Mail sent this way meets the basic rule at Gmail and Yahoo, but not the rule for bulk senders. Anyone sending in bulk must also add a digital signature (DKIM). Gmail and Outlook.com count bulk as 5,000 messages a day, and may refuse mail that falls short or send it to spam.

Delivery, technical: Only SPF passes here. That meets the requirement for all senders, SPF or DKIM, but bulk senders need both to pass. Google's Email sender guidelines, Yahoo's Sender Best Practices, and Microsoft's Outlook.com requirements for high volume senders all say so. Google and Microsoft draw the line at 5,000 messages a day, and mail that falls short may be rejected or marked as spam.

Detail 1, plain: The sending server is approved by o1.shop.example, which belongs to the sender.

Detail 1, technical: SPF passed for the HELO name o1.shop.example, which aligns with shop.example in relaxed mode only.

Fix 1, plain: Turn on email signing (DKIM) for shop.example in the settings of the service that sends this mail. It adds a digital signature with your domain to every message, and that signature still works when mail is forwarded.

Fix 1, technical: DMARC depends on SPF alone, and a forward breaks SPF. Turn on DKIM signing for shop.example at the sending service. Aligned DKIM lets DMARC pass, including after a forward.

Limit 1, plain: This page assumes the usual, looser domain match. A domain's DMARC setting can demand an exact match, and the headers don't show that setting.

Limit 1, technical: Alignment is computed in relaxed mode, the DMARC default, with strict mode beside it. adkim and aspf are set in the DMARC record, which is not in the headers.

Limit 2, plain: This page works out where the sender's organization begins from its own short list, so the looser domain match is its best reading, not a certainty.

Limit 2, technical: The organizational domain shop.example comes from a short built in suffix list, not from DNS or the full Public Suffix List that receivers use. Relaxed alignment here rests on it.

Sender signals, plain: Yes, as far as the headers show.

Sender signals, technical: No flag fired: DMARC passed for shop.example, and the display name, Reply-To, and From domain raise nothing.

Spam signals, plain: These headers can't say. They carry no spam rating from the receiving system that this page can read.

Spam signals, technical: No spam filter result that this page can read was written by the receiver.

Signals, nothing fired, plain: Nothing in the headers points to forgery or spam. That covers the headers only, because this page doesn't judge the message text, links, or attachments.

Signals, nothing fired, technical: Nothing in the headers points to forgery or spam. That is a statement about the headers only: the body, links and attachments are not examined.

## pass by DKIM known only by i=

Plain headline: This message passed the sender check (DMARC). It was signed on behalf of mail.shop.example. That belongs to shop.example, the domain in the From address, or to its parent domain.

Technical headline: DMARC at mx.receiver.example passed because DKIM i=@mail.shop.example s=s1 passed, and it aligns with the From domain shop.example (RFC5322.From) under relaxed alignment, through the organizational domain.

Cause, plain: A message passes when it's signed by, or sent for, the domain in its From address, and this one was.

Cause, technical: For shop.example, the pass comes from aligned DKIM, which still passes after a forward if nothing alters the signed headers or body.

Policy, plain: The message passed, so the sender's DMARC setting didn't come into play.

Policy, technical: shop.example publishes p=reject, which asks for failing mail to be refused. This message passed, so the policy did not come into play.

Delivery: none written

Detail 1, plain: The message was signed on behalf of mail.shop.example, which belongs to the sender.

Detail 1, technical: DKIM passed for i=@mail.shop.example s=s1, which aligns with shop.example in relaxed mode. No DKIM-Signature here shows its d=, so strict mode cannot be judged.

Detail 2, plain: The sending server is approved, but by bounce.mailer.example, not by the sender's own domain.

Detail 2, technical: SPF passed for bounce.mailer.example, which does not align with shop.example. A pass on another domain does not count for DMARC.

Fix 1, plain: Nothing needs fixing. If you want both checks to match, give the service that sends this mail a custom return address on shop.example (often called a custom return path).

Fix 1, technical: Alignment comes from DKIM alone, which is enough. For SPF to align too, set a custom Return-Path domain under shop.example at the sending service.

Limit 1, plain: This page assumes the usual, looser domain match. A domain's DMARC setting can demand an exact match, and the headers don't show that setting.

Limit 1, technical: Alignment is computed in relaxed mode, the DMARC default, with strict mode beside it. adkim and aspf are set in the DMARC record, which is not in the headers.

Limit 2, plain: The headers don't show the exact domain the signature used, only a name under it. It belongs to the sender's organization, so the usual, looser match holds.

Limit 2, technical: The DKIM result names only i=@mail.shop.example, and no DKIM-Signature here matches it, so its d= is not in the headers. RFC 6376 3.5 puts i= at or below d=, so relaxed alignment holds; strict alignment (adkim=s) cannot be judged.

Limit 3, plain: The sender could have written these check results. They say the message carries a valid digital signature (DKIM), but the headers hold no signature to back that.

Limit 3, technical: The only trusted Authentication-Results field (authserv-id mx.receiver.example) sits below the receiver's only Received stamp, where the sender could have written it. It reports dkim=pass, but the headers hold no DKIM-Signature, so nothing here backs that pass.

Sender signals, plain: Yes, as far as the headers show.

Sender signals, technical: No flag fired: DMARC passed for shop.example, and the display name, Reply-To, and From domain raise nothing.

Spam signals, plain: These headers can't say. They carry no spam rating from the receiving system that this page can read.

Spam signals, technical: No spam filter result that this page can read was written by the receiver.

Signals, nothing fired, plain: Nothing in the headers points to forgery or spam. That covers the headers only, because this page doesn't judge the message text, links, or attachments.

Signals, nothing fired, technical: Nothing in the headers points to forgery or spam. That is a statement about the headers only: the body, links and attachments are not examined.

## fail with DKIM known only by i=

Plain headline: This message failed the sender check (DMARC) even though it was signed on behalf of mail.shop.example. The receiving system reported a failure the headers don't explain.

Technical headline: DMARC at mx.receiver.example failed even though DKIM i=@mail.shop.example s=s1 passed and aligns with the From domain shop.example.

Cause, plain: The headers don't show the exact domain the signature used. If the sender's DMARC setting demands an exact domain match, that would explain the failure.

Cause, technical: The receiver reported dmarc=fail. The DKIM result names only i=@mail.shop.example, and no DKIM-Signature here matches it, so its d= is unknown. If d= is not exactly shop.example and the record sets adkim=s, that explains the failure; the headers show neither.

Policy, plain: shop.example's DMARC setting asks providers to refuse fake mail. The recipient's email provider refused this message.

Policy, technical: shop.example publishes p=reject, which asks for failing mail to be refused, and mx.receiver.example refused this message (dis=REJECT).

Delivery: none written

Detail 1, plain: The message was signed on behalf of mail.shop.example, which belongs to the sender.

Detail 1, technical: DKIM passed for i=@mail.shop.example s=s1, which aligns with shop.example in relaxed mode. No DKIM-Signature here shows its d=, so strict mode cannot be judged.

Detail 2, plain: The sending server is approved, but by bounce.mailer.example, not by the sender's own domain.

Detail 2, technical: SPF passed for bounce.mailer.example, which does not align with shop.example. A pass on another domain does not count for DMARC.

Fix 1, plain: Once the signature is fixed, you can also give the service that sends this mail a custom return address on shop.example. Services call it a custom return path or sending domain. It's optional.

Fix 1, technical: Second, after DKIM: set a custom Return-Path (bounce) domain under shop.example at the sending service so SPF aligns too.

Limit 1, plain: This page assumes the usual, looser domain match. A domain's DMARC setting can demand an exact match, and the headers don't show that setting.

Limit 1, technical: Alignment is computed in relaxed mode, the DMARC default, with strict mode beside it. adkim and aspf are set in the DMARC record, which is not in the headers.

Limit 2, plain: The headers don't show the exact domain the signature used, only a name under it. It belongs to the sender's organization, so the usual, looser match holds.

Limit 2, technical: The DKIM result names only i=@mail.shop.example, and no DKIM-Signature here matches it, so its d= is not in the headers. RFC 6376 3.5 puts i= at or below d=, so relaxed alignment holds; strict alignment (adkim=s) cannot be judged.

Limit 3, plain: The sender could have written these check results. They say the message carries a valid digital signature (DKIM), but the headers hold no signature to back that.

Limit 3, technical: The only trusted Authentication-Results field (authserv-id mx.receiver.example) sits below the receiver's only Received stamp, where the sender could have written it. It reports dkim=pass, but the headers hold no DKIM-Signature, so nothing here backs that pass.

Sender signals, plain: Maybe not. Treat this message with care.

Sender signals, technical: One signal says the author may not be who the From line shows.

Sender signal 1, plain: This message failed the sender check (DMARC), so nothing proves it came from shop.example.

Sender signal 1, technical: DMARC failed for the From domain shop.example (RFC5322.From), so no aligned SPF or DKIM pass vouches for the author domain.

Spam signals, plain: These headers can't say. They carry no spam rating from the receiving system that this page can read.

Spam signals, technical: No spam filter result that this page can read was written by the receiver.

## pass by an rsa-sha1 signature

Plain headline: This message passed the sender check (DMARC). It was signed by shop.example with an outdated method (rsa-sha1) that mail systems should no longer accept. That matches shop.example, the domain in the From address.

Technical headline: DMARC at mx.receiver.example passed because DKIM d=shop.example s=s1 passed (a=rsa-sha1, which RFC 8301 3.1 says verifiers must treat as failed), and it aligns with the From domain shop.example (RFC5322.From).

Cause, plain: A message passes when it's signed by, or sent for, the domain in its From address, and this one was. But the signature uses an outdated method (rsa-sha1), so mail systems that follow current rules would fail it.

Cause, technical: For shop.example, the pass comes from aligned DKIM, which still passes after a forward if nothing alters the signed headers or body. The signature uses rsa-sha1, which RFC 8301 3.1 has verifiers treat as failed, so receivers that follow it would fail this message.

Policy, plain: The message passed, so the sender's DMARC setting didn't come into play.

Policy, technical: shop.example publishes p=reject, which asks for failing mail to be refused. This message passed, so the policy did not come into play.

Delivery, plain: At mail providers that no longer accept the old method, this mail fails the sender check (DMARC). shop.example's DMARC setting then asks them to refuse it.

Delivery, technical: A verifier that follows RFC 8301 3.1 does not count this signature. Nothing else aligns with shop.example, so DMARC fails there, and the DMARC record of shop.example carries p=reject, which asks receivers to reject failing mail (RFC 9989 4.7).

Detail 1, plain: The message was signed by shop.example, but with an outdated method (rsa-sha1) that mail systems should no longer accept.

Detail 1, technical: DKIM passed for d=shop.example s=s1, which aligns with shop.example, but the signature uses rsa-sha1. RFC 8301 3.1 says verifiers must not accept rsa-sha1, so a receiver that follows it would not count this pass.

Detail 2, plain: The sending server is approved, but by bounce.mailer.example, not by the sender's own domain.

Detail 2, technical: SPF passed for bounce.mailer.example, which does not align with shop.example. A pass on another domain does not count for DMARC.

Fix 1, plain: Ask the service that sends this mail to sign with the current method (rsa-sha256). This message uses an old one (rsa-sha1) that mail systems following current rules no longer accept, so it may fail elsewhere.

Fix 1, technical: Sign with rsa-sha256 at the sending service instead of rsa-sha1 for d=shop.example. RFC 8301 3.1 has verifiers treat rsa-sha1 as failed, so this pass may not hold at other receivers.

Fix 2, plain: Nothing needs fixing. If you want both checks to match, give the service that sends this mail a custom return address on shop.example (often called a custom return path).

Fix 2, technical: Alignment comes from DKIM alone, which is enough. For SPF to align too, set a custom Return-Path domain under shop.example at the sending service.

Limit 1, plain: This page assumes the usual, looser domain match. A domain's DMARC setting can demand an exact match, and the headers don't show that setting.

Limit 1, technical: Alignment is computed in relaxed mode, the DMARC default, with strict mode beside it. adkim and aspf are set in the DMARC record, which is not in the headers.

Sender signals, plain: Yes, as far as the headers show.

Sender signals, technical: No flag fired: DMARC passed for shop.example, and the display name, Reply-To, and From domain raise nothing.

Spam signals, plain: These headers can't say. They carry no spam rating from the receiving system that this page can read.

Spam signals, technical: No spam filter result that this page can read was written by the receiver.

Signals, nothing fired, plain: Nothing in the headers points to forgery or spam. That covers the headers only, because this page doesn't judge the message text, links, or attachments.

Signals, nothing fired, technical: Nothing in the headers points to forgery or spam. That is a statement about the headers only: the body, links and attachments are not examined.

## fail with a list claim and nothing from before the list

Plain headline: This message failed the sender check (DMARC). It was signed by list.example and it came from a server that list.example allows. Neither of those is shop.example, the domain in the From address.

Technical headline: DMARC at mx.receiver.example failed because DKIM d=list.example s=l1 passed and SPF passed for the Return-Path domain list.example (RFC5321.MailFrom), but neither aligns with the From domain shop.example (RFC5322.From).

Cause, plain: The message says it came through the mailing list club.list.example. Anyone can write that, and the headers carry no record of the message before the list. The list may have broken the check, or the message may be forged to look like list mail.

Cause, technical: The message names the mailing list club.list.example and passed only for list.example. The List-Id and that pass are all the sender's to write, and no record from before the list is in the headers. So the list may have broken DMARC, or this is a forgery that borrowed a list's headers.

Policy, plain: shop.example's DMARC setting asks providers to refuse fake mail. The recipient's email provider refused this message.

Policy, technical: shop.example publishes p=reject, which asks for failing mail to be refused, and mx.receiver.example refused this message (dis=REJECT).

Delivery: none written

Detail 1, plain: The message was signed, but by list.example, not by the sender's own domain.

Detail 1, technical: DKIM passed for d=list.example s=l1, which does not align with shop.example. A pass on another domain does not count for DMARC.

Detail 2, plain: The sending server is approved, but by list.example, not by the sender's own domain.

Detail 2, technical: SPF passed for list.example, which does not align with shop.example. A pass on another domain does not count for DMARC.

Fix 1, plain: Don't trust this message on its word. Ask for a copy sent straight to you, without the list, and check that one. If nobody at shop.example sent it, treat it as forged.

Fix 1, technical: Judge the sender by a copy delivered straight to the mailbox. Nothing from before the list shows a pass, so this failure could come from the list or from a forgery that borrowed a list's headers. If nobody at shop.example sent it, treat it as forged.

Fix 2, plain: If you run the list and it did send this: have it send under its own address (it can keep the sender's name).

Fix 2, technical: If you run club.list.example and it did carry this message: have the list rewrite the From address to its own, or ARC-seal outgoing mail so receivers that trust the seal see the result from before the list.

Limit 1, plain: This page assumes the usual, looser domain match. A domain's DMARC setting can demand an exact match, and the headers don't show that setting.

Limit 1, technical: Alignment is computed in relaxed mode, the DMARC default, with strict mode beside it. adkim and aspf are set in the DMARC record, which is not in the headers.

Sender signals, plain: Maybe not. Treat this message with care.

Sender signals, technical: One signal says the author may not be who the From line shows.

Sender signal 1, plain: This message failed the sender check (DMARC), so nothing proves it came from shop.example.

Sender signal 1, technical: DMARC failed for the From domain shop.example (RFC5322.From), so no aligned SPF or DKIM pass vouches for the author domain.

Spam signals, plain: These headers can't say. They carry no spam rating from the receiving system that this page can read.

Spam signals, technical: No spam filter result that this page can read was written by the receiver.

## fail with a hidden character in the From domain

Plain headline: This message failed the sender check (DMARC). It was signed by shop.example and it came from a server that bounce.mailer.example allows. Neither of those is sh<U+200B>op.example, the domain in the From address.

Technical headline: DMARC at mx.receiver.example failed because DKIM d=shop.example s=s1 passed and SPF passed for the Return-Path domain bounce.mailer.example (RFC5321.MailFrom), but neither aligns with the From domain sh<U+200B>op.example (RFC5322.From).

Cause, plain: The sender's address only looks like shop.example. It hides a character, so no check that passed counts for it.

Cause, technical: The From domain sh<U+200B>op.example only looks like shop.example: it holds a hidden character, so nothing that passed, for shop.example or any other domain, aligns with it.

Policy, plain: sh<U+200B>op.example's DMARC setting asks providers to refuse fake mail. The recipient's email provider refused this message.

Policy, technical: sh<U+200B>op.example publishes p=reject, which asks for failing mail to be refused, and mx.receiver.example refused this message (dis=REJECT).

Delivery: none written

Detail 1, plain: The message was signed, but by shop.example, not by the sender's own domain.

Detail 1, technical: DKIM passed for d=shop.example s=s1, which does not align with sh<U+200B>op.example. A pass on another domain does not count for DMARC.

Detail 2, plain: The sending server is approved, but by bounce.mailer.example, not by the sender's own domain.

Detail 2, technical: SPF passed for bounce.mailer.example, which does not align with sh<U+200B>op.example. A pass on another domain does not count for DMARC.

Fix 1, plain: Treat this as a scam. The sender's address hides a character so it looks like shop.example. Report it as phishing and don't click its links or reply. If you copied the headers from a formatted view, copy the original message source and check again first.

Fix 1, technical: Treat the message as phishing: the From domain holds a hidden character, so it is not shop.example and nobody can register it. If you copied these headers from a formatted view rather than the message source, copy the source and decode it again first.

Flag 1, plain: The sender's address holds a hidden character, so it isn't shop.example even though it looks like it. No real address can be spelled that way, so this message is forged.

Flag 1, technical: The From domain sh<U+200B>op.example holds U+200B, an invisible character, so it is not shop.example. IDNA (RFC 5892) does not allow it here, so no registered domain is spelled that way.

Limit 1, plain: This page assumes the usual, looser domain match. A domain's DMARC setting can demand an exact match, and the headers don't show that setting.

Limit 1, technical: Alignment is computed in relaxed mode, the DMARC default, with strict mode beside it. adkim and aspf are set in the DMARC record, which is not in the headers.

Sender signals, plain: Maybe not. Treat this message with care.

Sender signals, technical: Two signals say the author may not be who the From line shows.

Sender signal 1, plain: This message failed the sender check (DMARC), so nothing proves it came from sh<U+200B>op.example.

Sender signal 1, technical: DMARC failed for the From domain sh<U+200B>op.example (RFC5322.From), so no aligned SPF or DKIM pass vouches for the author domain.

Sender signal 2, plain: The sender's address holds a hidden character, so it isn't shop.example even though it looks like it. No real address can be spelled that way, so this message is forged.

Sender signal 2, technical: The From domain sh<U+200B>op.example holds U+200B, an invisible character, so it is not shop.example. IDNA (RFC 5892) does not allow it here, so no registered domain is spelled that way.

Spam signals, plain: These headers can't say. They carry no spam rating from the receiving system that this page can read.

Spam signals, technical: No spam filter result that this page can read was written by the receiver.

## signals: pass with a forged display name and a reply address elsewhere

Plain headline: This message passed the sender check (DMARC). It was signed by notify.example, the domain in the From address, and came from a server it allows.

Technical headline: DMARC at mx.receiver.example passed because DKIM d=notify.example s=n1 passed and SPF passed for the Return-Path domain notify.example (RFC5321.MailFrom), and both align with the From domain notify.example (RFC5322.From).

Cause, plain: A message passes when it's signed by, or sent for, the domain in its From address, and this one was.

Cause, technical: For notify.example, both SPF and DKIM pass and align, so the message still passes after a forward that breaks SPF.

Policy, plain: The headers don't say what notify.example asks mail providers to do with fake mail.

Policy, technical: mx.receiver.example did not quote the DMARC policy of notify.example, so the headers do not show what a failure means for this domain. The record is in DNS, which this page does not read.

Delivery: none written

Detail 1, plain: The message was signed by notify.example, which belongs to the sender.

Detail 1, technical: DKIM passed for d=notify.example s=n1, which aligns with notify.example.

Detail 2, plain: The sending server is approved by notify.example, which belongs to the sender.

Detail 2, technical: SPF passed for notify.example, which aligns with notify.example.

Flag 1, plain: The name shown for the sender contains an address at bank.example, but the message comes from notify.example. Forged mail often does this.

Flag 1, technical: The display name shows an address at bank.example, while the real From domain is notify.example. That is a common impersonation layout.

Flag 2, plain: Replies go to a different company than the one in the From address. Check that you expected that.

Flag 2, technical: Replies go to other.example, a different organization from notify.example. Normal for some platforms and help desks; a phishing sign when unexpected.

Limit 1, plain: This page assumes the usual, looser domain match. A domain's DMARC setting can demand an exact match, and the headers don't show that setting.

Limit 1, technical: Alignment is computed in relaxed mode, the DMARC default, with strict mode beside it. adkim and aspf are set in the DMARC record, which is not in the headers.

Sender signals, plain: Maybe not. Treat this message with care.

Sender signals, technical: Two signals say the author may not be who the From line shows.

Sender signal 1, plain: The name shown for the sender contains an address at bank.example, but the message comes from notify.example. Forged mail often does this.

Sender signal 1, technical: The display name shows an address at bank.example, while the real From domain is notify.example. That is a common impersonation layout.

Sender signal 2, plain: Replies go to a different company than the one in the From address. Check that you expected that.

Sender signal 2, technical: Replies go to other.example, a different organization from notify.example. Normal for some platforms and help desks; a phishing sign when unexpected.

Spam signals, plain: These headers can't say. They carry no spam rating from the receiving system that this page can read.

Spam signals, technical: No spam filter result that this page can read was written by the receiver.

## signals: pass that Microsoft rated as spam

Plain headline: This message passed the sender check (DMARC). It was signed by shop.example, the domain in the From address, and came from a server it allows.

Technical headline: DMARC at Microsoft 365 passed because DKIM d=shop.example passed and SPF passed for the Return-Path domain shop.example (RFC5321.MailFrom), and both align with the From domain shop.example (RFC5322.From).

Cause, plain: A message passes when it's signed by, or sent for, the domain in its From address, and this one was. Microsoft's own sender check still passed it.

Cause, technical: For shop.example, both SPF and DKIM pass and align, so the message still passes after a forward that breaks SPF. Microsoft recorded compauth=pass reason=100, meaning SPF or DKIM passed and aligns with the From domain.

Policy, plain: The message passed, so the sender's DMARC setting didn't come into play.

Policy, technical: Microsoft recorded action=none; the message passed, so no action was needed.

Delivery, plain: Mail sent this way meets the rules Gmail, Yahoo, and Microsoft's Outlook.com set for proving who sent a message. Those rules also cover spam complaints and unsubscribe links, which the headers don't show.

Delivery, technical: SPF and DKIM both pass, and both align with the From domain shop.example, which publishes a DMARC record. That meets the authentication requirements for bulk senders. Google's Email sender guidelines, Yahoo's Sender Best Practices, and Microsoft's Outlook.com requirements for high volume senders all say so. Their spam rate and unsubscribe requirements are outside the headers.

Detail 1, plain: The message was signed by shop.example, which belongs to the sender.

Detail 1, technical: DKIM passed for d=shop.example, which aligns with shop.example.

Detail 2, plain: The sending server is approved by shop.example, which belongs to the sender.

Detail 2, technical: SPF passed for shop.example, which aligns with shop.example.

Detail 3, plain: Microsoft 365: Filed as spam.

Detail 3, technical: Microsoft 365, CAT SPM: Threat category: Spam.

Limit 1, plain: This page assumes the usual, looser domain match. A domain's DMARC setting can demand an exact match, and the headers don't show that setting.

Limit 1, technical: Alignment is computed in relaxed mode, the DMARC default, with strict mode beside it. adkim and aspf are set in the DMARC record, which is not in the headers.

Sender signals, plain: Yes, as far as the headers show.

Sender signals, technical: No flag fired: DMARC passed for shop.example, and the display name, Reply-To, and From domain raise nothing.

Spam signals, plain: Yes. The receiving system's filter rated it as spam or as a risk.

Spam signals, technical: Microsoft 365 recorded three results against this message.

Spam signal 1, plain: Microsoft 365: Filed as spam.

Spam signal 1, technical: Microsoft 365, CAT SPM: Threat category: Spam.

Spam signal 2, plain: Microsoft 365: Microsoft's spam filter decided this is spam.

Spam signal 2, technical: Microsoft 365, SFV SPM: Spam filtering marked it as spam.

Spam signal 3, plain: Microsoft 365: Rated as spam.

Spam signal 3, technical: Microsoft 365, SCL 5: Spam confidence level 5: spam.

## signals: pass with a filter result and nothing against it

Plain headline: This message passed the sender check (DMARC). It was signed by shop.example, the domain in the From address, and came from a server it allows.

Technical headline: DMARC at Microsoft 365 passed because DKIM d=shop.example passed and SPF passed for the Return-Path domain shop.example (RFC5321.MailFrom), and both align with the From domain shop.example (RFC5322.From).

Cause, plain: A message passes when it's signed by, or sent for, the domain in its From address, and this one was. Microsoft's own sender check still passed it.

Cause, technical: For shop.example, both SPF and DKIM pass and align, so the message still passes after a forward that breaks SPF. Microsoft recorded compauth=pass reason=100, meaning SPF or DKIM passed and aligns with the From domain.

Policy, plain: The message passed, so the sender's DMARC setting didn't come into play.

Policy, technical: Microsoft recorded action=none; the message passed, so no action was needed.

Delivery, plain: Mail sent this way meets the rules Gmail, Yahoo, and Microsoft's Outlook.com set for proving who sent a message. Those rules also cover spam complaints and unsubscribe links, which the headers don't show.

Delivery, technical: SPF and DKIM both pass, and both align with the From domain shop.example, which publishes a DMARC record. That meets the authentication requirements for bulk senders. Google's Email sender guidelines, Yahoo's Sender Best Practices, and Microsoft's Outlook.com requirements for high volume senders all say so. Their spam rate and unsubscribe requirements are outside the headers.

Detail 1, plain: The message was signed by shop.example, which belongs to the sender.

Detail 1, technical: DKIM passed for d=shop.example, which aligns with shop.example.

Detail 2, plain: The sending server is approved by shop.example, which belongs to the sender.

Detail 2, technical: SPF passed for shop.example, which aligns with shop.example.

Detail 3, plain: Microsoft 365: No threat was detected.

Detail 3, technical: Microsoft 365, CAT NONE: Threat category: No threat policy applied.

Limit 1, plain: This page assumes the usual, looser domain match. A domain's DMARC setting can demand an exact match, and the headers don't show that setting.

Limit 1, technical: Alignment is computed in relaxed mode, the DMARC default, with strict mode beside it. adkim and aspf are set in the DMARC record, which is not in the headers.

Sender signals, plain: Yes, as far as the headers show.

Sender signals, technical: No flag fired: DMARC passed for shop.example, and the display name, Reply-To, and From domain raise nothing.

Spam signals, plain: No. The receiving system's filter recorded nothing against it.

Spam signals, technical: Microsoft 365 recorded no spam, bulk or phishing result against this message.

Signals, nothing fired, plain: Nothing in the headers points to forgery or spam. That covers the headers only, because this page doesn't judge the message text, links, or attachments.

Signals, nothing fired, technical: Nothing in the headers points to forgery or spam. That is a statement about the headers only: the body, links and attachments are not examined.

## signature check: no key found

Plain headline: This message failed the sender check (DMARC). The signature didn't check out and it came from a server that bounce.mailer.example allows. Nothing that checked out matches shop.example, the domain in the From address.

Technical headline: DMARC at mx.receiver.example failed because DKIM d=shop.example s=s1 failed verification and SPF passed for the Return-Path domain bounce.mailer.example (RFC5321.MailFrom), and nothing that passed aligns with the From domain shop.example (RFC5322.From).

Cause, plain: The signature from shop.example didn't check out when the message arrived. Checked today (November 13, 2026): The signature from shop.example points to a published key (DKIM key) that isn't there for shop.example. Nobody can check the signature without it, so mail signed this way fails. Ask the service that sends this mail for the DNS setting to add.

Cause, technical: The DKIM signature from shop.example did not verify at mx.receiver.example. Checked today (November 13, 2026): The TXT query for s1._domainkey.shop.example returned NXDOMAIN, so no DKIM key record exists there. RFC 6376 6.1.2 has a verifier return PERMFAIL (no key for signature). SPF passed only for bounce.mailer.example, which is not shop.example.

Policy, plain: shop.example's DMARC setting asks providers to refuse fake mail. The recipient's email provider refused this message.

Policy, technical: shop.example publishes p=reject, which asks for failing mail to be refused, and mx.receiver.example refused this message (dis=REJECT).

Delivery, plain: shop.example's DMARC setting asks mail providers to refuse mail that fails this way. Expect the ones that follow it to refuse every message with this problem.

Delivery, technical: The DMARC record of shop.example carries p=reject, which asks receivers to reject mail that fails DMARC (RFC 9989 4.7). Every message that fails this way falls under it. A receiver is not required to honor the request, so some copies may still arrive.

Detail 1, plain: The signature from shop.example didn't check out. Checked today (November 13, 2026): The signature from shop.example points to a published key (DKIM key) that isn't there for shop.example. Nobody can check the signature without it, so mail signed this way fails. Ask the service that sends this mail for the DNS setting to add.

Detail 1, technical: DKIM failed for d=shop.example s=s1. Checked today (November 13, 2026): The TXT query for s1._domainkey.shop.example returned NXDOMAIN, so no DKIM key record exists there. RFC 6376 6.1.2 has a verifier return PERMFAIL (no key for signature).

Detail 2, plain: The sending server is approved, but by bounce.mailer.example, not by the sender's own domain.

Detail 2, technical: SPF passed for bounce.mailer.example, which does not align with shop.example. A pass on another domain does not count for DMARC.

Fix 1, plain: Ask the service that sends this mail for the DKIM setting for shop.example. It has a name and a value.

Fix 1, technical: Get the DKIM key record for selector s1 from the sending service.

Fix 2, plain: Ask whoever manages the DNS for shop.example to add it at the company that hosts the DNS.

Fix 2, technical: Publish it as a TXT record, or as the CNAME the service gives, at s1._domainkey.shop.example.

Fix 3, plain: Send a new message and check that one here.

Fix 3, technical: Send a new message and verify it again. Receivers that already judged this one keep their result.

Limit 1, plain: This page assumes the usual, looser domain match. A domain's DMARC setting can demand an exact match, and the headers don't show that setting.

Limit 1, technical: Alignment is computed in relaxed mode, the DMARC default, with strict mode beside it. adkim and aspf are set in the DMARC record, which is not in the headers.

Sender signals, plain: Maybe not. Treat this message with care.

Sender signals, technical: One signal says the author may not be who the From line shows.

Sender signal 1, plain: This message failed the sender check (DMARC), so nothing proves it came from shop.example.

Sender signal 1, technical: DMARC failed for the From domain shop.example (RFC5322.From), so no aligned SPF or DKIM pass vouches for the author domain.

Spam signals, plain: These headers can't say. They carry no spam rating from the receiving system that this page can read.

Spam signals, technical: No spam filter result that this page can read was written by the receiver.

Signature check, plain: Checked today, November 13, 2026. What the recipient's email provider recorded when the message arrived is shown separately.

Signature check, technical: Checked November 13, 2026 from the pasted text. Each key was looked up over DNS over HTTPS at cloudflare-dns.com, and each signature was verified in this browser (RFC 6376 3.7). The results mx.receiver.example recorded at delivery are a separate fact and are not changed by this check.

Signature check label, plain: Cause found

Signature check, on arrival, plain: The recipient's email provider recorded that this signature failed when the message arrived.

Signature check, on arrival, technical: mx.receiver.example recorded dkim=fail for d=shop.example s=s1 at delivery.

Signature check, today, plain: The signature from shop.example points to a published key (DKIM key) that isn't there for shop.example. Nobody can check the signature without it, so mail signed this way fails. Ask the service that sends this mail for the DNS setting to add.

Signature check, today, technical: The TXT query for s1._domainkey.shop.example returned NXDOMAIN, so no DKIM key record exists there. RFC 6376 6.1.2 has a verifier return PERMFAIL (no key for signature).

Signature check, who fixes it, plain: Whoever manages the DNS for shop.example fixes this, with the setting from the service that sends this mail.

Signature check, who fixes it, technical: Whoever manages the DNS for shop.example publishes the record, and the sending service supplies it.

Signature check step 1, plain: Ask the service that sends this mail for the DKIM setting for shop.example. It has a name and a value.

Signature check step 1, technical: Get the DKIM key record for selector s1 from the sending service.

Signature check step 2, plain: Ask whoever manages the DNS for shop.example to add it at the company that hosts the DNS.

Signature check step 2, technical: Publish it as a TXT record, or as the CNAME the service gives, at s1._domainkey.shop.example.

Signature check step 3, plain: Send a new message and check that one here.

Signature check step 3, technical: Send a new message and verify it again. Receivers that already judged this one keep their result.

## signature check: no key at the end of a CNAME

Plain headline: This message failed the sender check (DMARC). The signature didn't check out and it came from a server that bounce.mailer.example allows. Nothing that checked out matches shop.example, the domain in the From address.

Technical headline: DMARC at mx.receiver.example failed because DKIM d=shop.example s=s1 failed verification and SPF passed for the Return-Path domain bounce.mailer.example (RFC5321.MailFrom), and nothing that passed aligns with the From domain shop.example (RFC5322.From).

Cause, plain: The signature from shop.example didn't check out when the message arrived. Checked today (November 13, 2026): The signature from shop.example points to a published key (DKIM key) that isn't there for shop.example. Nobody can check the signature without it, so mail signed this way fails. Ask the service that sends this mail for the DNS setting to add.

Cause, technical: The DKIM signature from shop.example did not verify at mx.receiver.example. Checked today (November 13, 2026): The TXT query for s1._domainkey.shop.example returned NXDOMAIN, so no DKIM key record exists there. The name is a CNAME to s1.dkim.mailer.example. RFC 6376 6.1.2 has a verifier return PERMFAIL (no key for signature). SPF passed only for bounce.mailer.example, which is not shop.example.

Policy, plain: shop.example's DMARC setting asks providers to refuse fake mail. The recipient's email provider refused this message.

Policy, technical: shop.example publishes p=reject, which asks for failing mail to be refused, and mx.receiver.example refused this message (dis=REJECT).

Delivery, plain: shop.example's DMARC setting asks mail providers to refuse mail that fails this way. Expect the ones that follow it to refuse every message with this problem.

Delivery, technical: The DMARC record of shop.example carries p=reject, which asks receivers to reject mail that fails DMARC (RFC 9989 4.7). Every message that fails this way falls under it. A receiver is not required to honor the request, so some copies may still arrive.

Detail 1, plain: The signature from shop.example didn't check out. Checked today (November 13, 2026): The signature from shop.example points to a published key (DKIM key) that isn't there for shop.example. Nobody can check the signature without it, so mail signed this way fails. Ask the service that sends this mail for the DNS setting to add.

Detail 1, technical: DKIM failed for d=shop.example s=s1. Checked today (November 13, 2026): The TXT query for s1._domainkey.shop.example returned NXDOMAIN, so no DKIM key record exists there. The name is a CNAME to s1.dkim.mailer.example. RFC 6376 6.1.2 has a verifier return PERMFAIL (no key for signature).

Detail 2, plain: The sending server is approved, but by bounce.mailer.example, not by the sender's own domain.

Detail 2, technical: SPF passed for bounce.mailer.example, which does not align with shop.example. A pass on another domain does not count for DMARC.

Fix 1, plain: Ask the service that sends this mail for the DKIM setting for shop.example. It has a name and a value.

Fix 1, technical: Get the DKIM key record for selector s1 from the sending service.

Fix 2, plain: Ask whoever manages the DNS for shop.example to add it at the company that hosts the DNS.

Fix 2, technical: s1._domainkey.shop.example is a CNAME to s1.dkim.mailer.example, which has no TXT record. The key belongs at that target, usually in the sending service's own zone.

Fix 3, plain: Send a new message and check that one here.

Fix 3, technical: Send a new message and verify it again. Receivers that already judged this one keep their result.

Limit 1, plain: This page assumes the usual, looser domain match. A domain's DMARC setting can demand an exact match, and the headers don't show that setting.

Limit 1, technical: Alignment is computed in relaxed mode, the DMARC default, with strict mode beside it. adkim and aspf are set in the DMARC record, which is not in the headers.

Sender signals, plain: Maybe not. Treat this message with care.

Sender signals, technical: One signal says the author may not be who the From line shows.

Sender signal 1, plain: This message failed the sender check (DMARC), so nothing proves it came from shop.example.

Sender signal 1, technical: DMARC failed for the From domain shop.example (RFC5322.From), so no aligned SPF or DKIM pass vouches for the author domain.

Spam signals, plain: These headers can't say. They carry no spam rating from the receiving system that this page can read.

Spam signals, technical: No spam filter result that this page can read was written by the receiver.

Signature check, plain: Checked today, November 13, 2026. What the recipient's email provider recorded when the message arrived is shown separately.

Signature check, technical: Checked November 13, 2026 from the pasted text. Each key was looked up over DNS over HTTPS at cloudflare-dns.com, and each signature was verified in this browser (RFC 6376 3.7). The results mx.receiver.example recorded at delivery are a separate fact and are not changed by this check.

Signature check label, plain: Cause found

Signature check, on arrival, plain: The recipient's email provider recorded that this signature failed when the message arrived.

Signature check, on arrival, technical: mx.receiver.example recorded dkim=fail for d=shop.example s=s1 at delivery.

Signature check, today, plain: The signature from shop.example points to a published key (DKIM key) that isn't there for shop.example. Nobody can check the signature without it, so mail signed this way fails. Ask the service that sends this mail for the DNS setting to add.

Signature check, today, technical: The TXT query for s1._domainkey.shop.example returned NXDOMAIN, so no DKIM key record exists there. The name is a CNAME to s1.dkim.mailer.example. RFC 6376 6.1.2 has a verifier return PERMFAIL (no key for signature).

Signature check, who fixes it, plain: Whoever manages the DNS for shop.example fixes this, with the setting from the service that sends this mail.

Signature check, who fixes it, technical: Whoever manages the DNS for shop.example publishes the record, and the sending service supplies it.

Signature check step 1, plain: Ask the service that sends this mail for the DKIM setting for shop.example. It has a name and a value.

Signature check step 1, technical: Get the DKIM key record for selector s1 from the sending service.

Signature check step 2, plain: Ask whoever manages the DNS for shop.example to add it at the company that hosts the DNS.

Signature check step 2, technical: s1._domainkey.shop.example is a CNAME to s1.dkim.mailer.example, which has no TXT record. The key belongs at that target, usually in the sending service's own zone.

Signature check step 3, plain: Send a new message and check that one here.

Signature check step 3, technical: Send a new message and verify it again. Receivers that already judged this one keep their result.

## signature check: key revoked

Plain headline: This message failed the sender check (DMARC). The signature didn't check out and it came from a server that bounce.mailer.example allows. Nothing that checked out matches shop.example, the domain in the From address.

Technical headline: DMARC at mx.receiver.example failed because DKIM d=shop.example s=s1 failed verification and SPF passed for the Return-Path domain bounce.mailer.example (RFC5321.MailFrom), and nothing that passed aligns with the From domain shop.example (RFC5322.From).

Cause, plain: The signature from shop.example didn't check out when the message arrived. Checked today (November 13, 2026): The key for this signature from shop.example was switched off on purpose (revoked). Mail signed with it fails. Ask the service that sends this mail to sign with its current key.

Cause, technical: The DKIM signature from shop.example did not verify at mx.receiver.example. Checked today (November 13, 2026): The key record at s1._domainkey.shop.example has an empty p=, which RFC 6376 3.6.1 defines as a revoked key. A verifier returns PERMFAIL (key revoked). SPF passed only for bounce.mailer.example, which is not shop.example.

Policy, plain: shop.example's DMARC setting asks providers to refuse fake mail. The recipient's email provider refused this message.

Policy, technical: shop.example publishes p=reject, which asks for failing mail to be refused, and mx.receiver.example refused this message (dis=REJECT).

Delivery, plain: shop.example's DMARC setting asks mail providers to refuse mail that fails this way. Expect the ones that follow it to refuse every message with this problem.

Delivery, technical: The DMARC record of shop.example carries p=reject, which asks receivers to reject mail that fails DMARC (RFC 9989 4.7). Every message that fails this way falls under it. A receiver is not required to honor the request, so some copies may still arrive.

Detail 1, plain: The signature from shop.example didn't check out. Checked today (November 13, 2026): The key for this signature from shop.example was switched off on purpose (revoked). Mail signed with it fails. Ask the service that sends this mail to sign with its current key.

Detail 1, technical: DKIM failed for d=shop.example s=s1. Checked today (November 13, 2026): The key record at s1._domainkey.shop.example has an empty p=, which RFC 6376 3.6.1 defines as a revoked key. A verifier returns PERMFAIL (key revoked).

Detail 2, plain: The sending server is approved, but by bounce.mailer.example, not by the sender's own domain.

Detail 2, technical: SPF passed for bounce.mailer.example, which does not align with shop.example. A pass on another domain does not count for DMARC.

Fix 1, plain: Ask the service that sends this mail which key it signs mail from shop.example with now.

Fix 1, technical: An empty p= at s1._domainkey.shop.example is deliberate. Find which selector the sending service signs shop.example with now.

Fix 2, plain: If it gives you a new DNS setting, ask whoever manages the DNS for shop.example to add it.

Fix 2, technical: Publish the record for the current selector if it is not in DNS yet.

Fix 3, plain: Send a new message and check that one here.

Fix 3, technical: Send a new message and verify it again. Receivers that already judged this one keep their result.

Limit 1, plain: This page assumes the usual, looser domain match. A domain's DMARC setting can demand an exact match, and the headers don't show that setting.

Limit 1, technical: Alignment is computed in relaxed mode, the DMARC default, with strict mode beside it. adkim and aspf are set in the DMARC record, which is not in the headers.

Sender signals, plain: Maybe not. Treat this message with care.

Sender signals, technical: One signal says the author may not be who the From line shows.

Sender signal 1, plain: This message failed the sender check (DMARC), so nothing proves it came from shop.example.

Sender signal 1, technical: DMARC failed for the From domain shop.example (RFC5322.From), so no aligned SPF or DKIM pass vouches for the author domain.

Spam signals, plain: These headers can't say. They carry no spam rating from the receiving system that this page can read.

Spam signals, technical: No spam filter result that this page can read was written by the receiver.

Signature check, plain: Checked today, November 13, 2026. What the recipient's email provider recorded when the message arrived is shown separately.

Signature check, technical: Checked November 13, 2026 from the pasted text. Each key was looked up over DNS over HTTPS at cloudflare-dns.com, and each signature was verified in this browser (RFC 6376 3.7). The results mx.receiver.example recorded at delivery are a separate fact and are not changed by this check.

Signature check label, plain: Cause found

Signature check, on arrival, plain: The recipient's email provider recorded that this signature failed when the message arrived.

Signature check, on arrival, technical: mx.receiver.example recorded dkim=fail for d=shop.example s=s1 at delivery.

Signature check, today, plain: The key for this signature from shop.example was switched off on purpose (revoked). Mail signed with it fails. Ask the service that sends this mail to sign with its current key.

Signature check, today, technical: The key record at s1._domainkey.shop.example has an empty p=, which RFC 6376 3.6.1 defines as a revoked key. A verifier returns PERMFAIL (key revoked).

Signature check, who fixes it, plain: The service that sends this mail fixes this, in its signing settings.

Signature check, who fixes it, technical: The sending service chooses the key it signs with.

Signature check step 1, plain: Ask the service that sends this mail which key it signs mail from shop.example with now.

Signature check step 1, technical: An empty p= at s1._domainkey.shop.example is deliberate. Find which selector the sending service signs shop.example with now.

Signature check step 2, plain: If it gives you a new DNS setting, ask whoever manages the DNS for shop.example to add it.

Signature check step 2, technical: Publish the record for the current selector if it is not in DNS yet.

Signature check step 3, plain: Send a new message and check that one here.

Signature check step 3, technical: Send a new message and verify it again. Receivers that already judged this one keep their result.

## signature check: key written wrong

Plain headline: This message failed the sender check (DMARC). The signature didn't check out and it came from a server that bounce.mailer.example allows. Nothing that checked out matches shop.example, the domain in the From address.

Technical headline: DMARC at mx.receiver.example failed because DKIM d=shop.example s=s1 failed verification and SPF passed for the Return-Path domain bounce.mailer.example (RFC5321.MailFrom), and nothing that passed aligns with the From domain shop.example (RFC5322.From).

Cause, plain: The signature from shop.example didn't check out when the message arrived. Checked today (November 13, 2026): The published key (DKIM key) for shop.example is there but written wrong, so the signature can't be checked. Copy it again from the settings of the service that sends this mail.

Cause, technical: The DKIM signature from shop.example did not verify at mx.receiver.example. Checked today (November 13, 2026): The TXT record at s1._domainkey.shop.example is not a usable DKIM key record: p= is not base64. RFC 6376 6.1.2 has verifiers ignore malformed key records. SPF passed only for bounce.mailer.example, which is not shop.example.

Policy, plain: shop.example's DMARC setting asks providers to refuse fake mail. The recipient's email provider refused this message.

Policy, technical: shop.example publishes p=reject, which asks for failing mail to be refused, and mx.receiver.example refused this message (dis=REJECT).

Delivery, plain: shop.example's DMARC setting asks mail providers to refuse mail that fails this way. Expect the ones that follow it to refuse every message with this problem.

Delivery, technical: The DMARC record of shop.example carries p=reject, which asks receivers to reject mail that fails DMARC (RFC 9989 4.7). Every message that fails this way falls under it. A receiver is not required to honor the request, so some copies may still arrive.

Detail 1, plain: The signature from shop.example didn't check out. Checked today (November 13, 2026): The published key (DKIM key) for shop.example is there but written wrong, so the signature can't be checked. Copy it again from the settings of the service that sends this mail.

Detail 1, technical: DKIM failed for d=shop.example s=s1. Checked today (November 13, 2026): The TXT record at s1._domainkey.shop.example is not a usable DKIM key record: p= is not base64. RFC 6376 6.1.2 has verifiers ignore malformed key records.

Detail 2, plain: The sending server is approved, but by bounce.mailer.example, not by the sender's own domain.

Detail 2, technical: SPF passed for bounce.mailer.example, which does not align with shop.example. A pass on another domain does not count for DMARC.

Fix 1, plain: Open the settings of the service that sends this mail and copy the DKIM value for shop.example again, all of it.

Fix 1, technical: Copy the key record for selector s1 from the sending service again, whole.

Fix 2, plain: Ask whoever manages the DNS for shop.example to replace the value, with no extra spaces, quotation marks, or line breaks.

Fix 2, technical: Replace the TXT value at s1._domainkey.shop.example. Common faults are a truncated p=, a pasted line break, stray quotation marks, and two records at one name.

Fix 3, plain: Send a new message and check that one here.

Fix 3, technical: Send a new message and verify it again. Receivers that already judged this one keep their result.

Limit 1, plain: This page assumes the usual, looser domain match. A domain's DMARC setting can demand an exact match, and the headers don't show that setting.

Limit 1, technical: Alignment is computed in relaxed mode, the DMARC default, with strict mode beside it. adkim and aspf are set in the DMARC record, which is not in the headers.

Sender signals, plain: Maybe not. Treat this message with care.

Sender signals, technical: One signal says the author may not be who the From line shows.

Sender signal 1, plain: This message failed the sender check (DMARC), so nothing proves it came from shop.example.

Sender signal 1, technical: DMARC failed for the From domain shop.example (RFC5322.From), so no aligned SPF or DKIM pass vouches for the author domain.

Spam signals, plain: These headers can't say. They carry no spam rating from the receiving system that this page can read.

Spam signals, technical: No spam filter result that this page can read was written by the receiver.

Signature check, plain: Checked today, November 13, 2026. What the recipient's email provider recorded when the message arrived is shown separately.

Signature check, technical: Checked November 13, 2026 from the pasted text. Each key was looked up over DNS over HTTPS at cloudflare-dns.com, and each signature was verified in this browser (RFC 6376 3.7). The results mx.receiver.example recorded at delivery are a separate fact and are not changed by this check.

Signature check label, plain: Cause found

Signature check, on arrival, plain: The recipient's email provider recorded that this signature failed when the message arrived.

Signature check, on arrival, technical: mx.receiver.example recorded dkim=fail for d=shop.example s=s1 at delivery.

Signature check, today, plain: The published key (DKIM key) for shop.example is there but written wrong, so the signature can't be checked. Copy it again from the settings of the service that sends this mail.

Signature check, today, technical: The TXT record at s1._domainkey.shop.example is not a usable DKIM key record: p= is not base64. RFC 6376 6.1.2 has verifiers ignore malformed key records.

Signature check, who fixes it, plain: Whoever manages the DNS for shop.example fixes this.

Signature check, who fixes it, technical: Whoever manages the DNS for shop.example repairs the record.

Signature check step 1, plain: Open the settings of the service that sends this mail and copy the DKIM value for shop.example again, all of it.

Signature check step 1, technical: Copy the key record for selector s1 from the sending service again, whole.

Signature check step 2, plain: Ask whoever manages the DNS for shop.example to replace the value, with no extra spaces, quotation marks, or line breaks.

Signature check step 2, technical: Replace the TXT value at s1._domainkey.shop.example. Common faults are a truncated p=, a pasted line break, stray quotation marks, and two records at one name.

Signature check step 3, plain: Send a new message and check that one here.

Signature check step 3, technical: Send a new message and verify it again. Receivers that already judged this one keep their result.

## signature check: key too short

Plain headline: This message failed the sender check (DMARC). The signature didn't check out and it came from a server that bounce.mailer.example allows. Nothing that checked out matches shop.example, the domain in the From address.

Technical headline: DMARC at mx.receiver.example failed because DKIM d=shop.example s=s1 failed verification and SPF passed for the Return-Path domain bounce.mailer.example (RFC5321.MailFrom), and nothing that passed aligns with the From domain shop.example (RFC5322.From).

Cause, plain: The signature from shop.example didn't check out when the message arrived. Checked today (November 13, 2026): The published key (DKIM key) for shop.example is too short for mail systems to trust. Ask the service that sends this mail for a longer one.

Cause, technical: The DKIM signature from shop.example did not verify at mx.receiver.example. Checked today (November 13, 2026): The RSA key at s1._domainkey.shop.example is 512 bits. RFC 8301 3.2 says verifiers MUST NOT consider signatures using RSA keys of less than 1024 bits as valid. SPF passed only for bounce.mailer.example, which is not shop.example.

Policy, plain: shop.example's DMARC setting asks providers to refuse fake mail. The recipient's email provider refused this message.

Policy, technical: shop.example publishes p=reject, which asks for failing mail to be refused, and mx.receiver.example refused this message (dis=REJECT).

Delivery, plain: shop.example's DMARC setting asks mail providers to refuse mail that fails this way. Expect the ones that follow it to refuse every message with this problem.

Delivery, technical: The DMARC record of shop.example carries p=reject, which asks receivers to reject mail that fails DMARC (RFC 9989 4.7). Every message that fails this way falls under it. A receiver is not required to honor the request, so some copies may still arrive.

Detail 1, plain: The signature from shop.example didn't check out. Checked today (November 13, 2026): The published key (DKIM key) for shop.example is too short for mail systems to trust. Ask the service that sends this mail for a longer one.

Detail 1, technical: DKIM failed for d=shop.example s=s1. Checked today (November 13, 2026): The RSA key at s1._domainkey.shop.example is 512 bits. RFC 8301 3.2 says verifiers MUST NOT consider signatures using RSA keys of less than 1024 bits as valid.

Detail 2, plain: The sending server is approved, but by bounce.mailer.example, not by the sender's own domain.

Detail 2, technical: SPF passed for bounce.mailer.example, which does not align with shop.example. A pass on another domain does not count for DMARC.

Fix 1, plain: Ask the service that sends this mail to make a new, longer key for shop.example.

Fix 1, technical: Generate a 2048-bit RSA key at the sending service under a new selector. RFC 8301 3.2 says signers SHOULD use at least 2048 bits.

Fix 2, plain: Ask whoever manages the DNS for shop.example to add the new DNS setting it gives you.

Fix 2, technical: Publish the new record, then retire s1._domainkey.shop.example.

Fix 3, plain: Send a new message and check that one here.

Fix 3, technical: Send a new message and verify it again. Receivers that already judged this one keep their result.

Limit 1, plain: This page assumes the usual, looser domain match. A domain's DMARC setting can demand an exact match, and the headers don't show that setting.

Limit 1, technical: Alignment is computed in relaxed mode, the DMARC default, with strict mode beside it. adkim and aspf are set in the DMARC record, which is not in the headers.

Sender signals, plain: Maybe not. Treat this message with care.

Sender signals, technical: One signal says the author may not be who the From line shows.

Sender signal 1, plain: This message failed the sender check (DMARC), so nothing proves it came from shop.example.

Sender signal 1, technical: DMARC failed for the From domain shop.example (RFC5322.From), so no aligned SPF or DKIM pass vouches for the author domain.

Spam signals, plain: These headers can't say. They carry no spam rating from the receiving system that this page can read.

Spam signals, technical: No spam filter result that this page can read was written by the receiver.

Signature check, plain: Checked today, November 13, 2026. What the recipient's email provider recorded when the message arrived is shown separately.

Signature check, technical: Checked November 13, 2026 from the message file. Each key was looked up over DNS over HTTPS at cloudflare-dns.com, and each signature was verified in this browser (RFC 6376 3.7). The results mx.receiver.example recorded at delivery are a separate fact and are not changed by this check.

Signature check label, plain: Cause found

Signature check, on arrival, plain: The recipient's email provider recorded that this signature failed when the message arrived.

Signature check, on arrival, technical: mx.receiver.example recorded dkim=fail for d=shop.example s=s1 at delivery.

Signature check, today, plain: The published key (DKIM key) for shop.example is too short for mail systems to trust. Ask the service that sends this mail for a longer one.

Signature check, today, technical: The RSA key at s1._domainkey.shop.example is 512 bits. RFC 8301 3.2 says verifiers MUST NOT consider signatures using RSA keys of less than 1024 bits as valid.

Signature check, who fixes it, plain: The service that sends this mail makes a new key, and whoever manages the DNS for shop.example adds it.

Signature check, who fixes it, technical: The sending service generates the key, and whoever manages the DNS for shop.example publishes it.

Signature check step 1, plain: Ask the service that sends this mail to make a new, longer key for shop.example.

Signature check step 1, technical: Generate a 2048-bit RSA key at the sending service under a new selector. RFC 8301 3.2 says signers SHOULD use at least 2048 bits.

Signature check step 2, plain: Ask whoever manages the DNS for shop.example to add the new DNS setting it gives you.

Signature check step 2, technical: Publish the new record, then retire s1._domainkey.shop.example.

Signature check step 3, plain: Send a new message and check that one here.

Signature check step 3, technical: Send a new message and verify it again. Receivers that already judged this one keep their result.

## signature check: no answer

Plain headline: This message failed the sender check (DMARC). The signature didn't check out and it came from a server that bounce.mailer.example allows. Nothing that checked out matches shop.example, the domain in the From address.

Technical headline: DMARC at mx.receiver.example failed because DKIM d=shop.example s=s1 failed verification and SPF passed for the Return-Path domain bounce.mailer.example (RFC5321.MailFrom), and nothing that passed aligns with the From domain shop.example (RFC5322.From).

Cause, plain: The message was changed after it was signed, or the signature doesn't match the sender's published key.

Cause, technical: The DKIM signature from shop.example did not verify at mx.receiver.example: something changed the signed part of the message after signing, or the key in DNS does not match. SPF passed only for bounce.mailer.example, which is not shop.example.

Policy, plain: shop.example's DMARC setting asks providers to refuse fake mail. The recipient's email provider refused this message.

Policy, technical: shop.example publishes p=reject, which asks for failing mail to be refused, and mx.receiver.example refused this message (dis=REJECT).

Delivery, plain: shop.example's DMARC setting asks mail providers to refuse mail that fails this way. Expect the ones that follow it to refuse every message with this problem.

Delivery, technical: The DMARC record of shop.example carries p=reject, which asks receivers to reject mail that fails DMARC (RFC 9989 4.7). Every message that fails this way falls under it. A receiver is not required to honor the request, so some copies may still arrive.

Detail 1, plain: The signature from shop.example didn't check out.

Detail 1, technical: DKIM failed for d=shop.example s=s1. Something changed the signed headers or body after signing, or the key in DNS does not match; the headers cannot show which.

Detail 2, plain: The sending server is approved, but by bounce.mailer.example, not by the sender's own domain.

Detail 2, technical: SPF passed for bounce.mailer.example, which does not align with shop.example. A pass on another domain does not count for DMARC.

Fix 1, plain: Ask whoever manages your mail whether anything adds a footer, a disclaimer, or tracking links after messages leave the service that sends this mail. That's the usual cause of a broken signature.

Fix 1, technical: The signature from d=shop.example broke between signing and mx.receiver.example. Look for anything that edits mail after the sending service signs it (a gateway, footer, disclaimer, or link rewriting), and check that the key at s1._domainkey.shop.example is the one it signs with.

Limit 1, plain: This page assumes the usual, looser domain match. A domain's DMARC setting can demand an exact match, and the headers don't show that setting.

Limit 1, technical: Alignment is computed in relaxed mode, the DMARC default, with strict mode beside it. adkim and aspf are set in the DMARC record, which is not in the headers.

Sender signals, plain: Maybe not. Treat this message with care.

Sender signals, technical: One signal says the author may not be who the From line shows.

Sender signal 1, plain: This message failed the sender check (DMARC), so nothing proves it came from shop.example.

Sender signal 1, technical: DMARC failed for the From domain shop.example (RFC5322.From), so no aligned SPF or DKIM pass vouches for the author domain.

Spam signals, plain: These headers can't say. They carry no spam rating from the receiving system that this page can read.

Spam signals, technical: No spam filter result that this page can read was written by the receiver.

Signature check, plain: Checked today, November 13, 2026. What the recipient's email provider recorded when the message arrived is shown separately.

Signature check, technical: Checked November 13, 2026 from the pasted text. Each key was looked up over DNS over HTTPS at cloudflare-dns.com, and each signature was verified in this browser (RFC 6376 3.7). The results mx.receiver.example recorded at delivery are a separate fact and are not changed by this check.

Signature check label, plain: No answer

Signature check, on arrival, plain: The recipient's email provider recorded that this signature failed when the message arrived.

Signature check, on arrival, technical: mx.receiver.example recorded dkim=fail for d=shop.example s=s1 at delivery.

Signature check, today, plain: The lookup got no answer, so this check didn't run. Try again in a minute.

Signature check, today, technical: The TXT query for s1._domainkey.shop.example over DNS over HTTPS returned no answer before the timeout. Nothing was verified, and this says nothing about the key.

## signature check: checks out

Plain headline: This message passed the sender check (DMARC). It was signed by shop.example, the domain in the From address.

Technical headline: DMARC at mx.receiver.example passed because DKIM d=shop.example s=s1 passed, and it aligns with the From domain shop.example (RFC5322.From).

Cause, plain: A message passes when it's signed by, or sent for, the domain in its From address, and this one was.

Cause, technical: For shop.example, the pass comes from aligned DKIM, which still passes after a forward if nothing alters the signed headers or body.

Policy, plain: The message passed, so the sender's DMARC setting didn't come into play.

Policy, technical: shop.example publishes p=reject, which asks for failing mail to be refused. This message passed, so the policy did not come into play.

Delivery, plain: Mail sent this way meets the rules Gmail, Yahoo, and Microsoft's Outlook.com set for proving who sent a message. Those rules also cover spam complaints and unsubscribe links, which the headers don't show.

Delivery, technical: SPF and DKIM both pass, and one aligns with the From domain shop.example, which publishes a DMARC record. That meets the authentication requirements for bulk senders. Google's Email sender guidelines, Yahoo's Sender Best Practices, and Microsoft's Outlook.com requirements for high volume senders all say so. Their spam rate and unsubscribe requirements are outside the headers.

Detail 1, plain: The message was signed by shop.example, which belongs to the sender.

Detail 1, technical: DKIM passed for d=shop.example s=s1, which aligns with shop.example.

Detail 2, plain: The sending server is approved, but by bounce.mailer.example, not by the sender's own domain.

Detail 2, technical: SPF passed for bounce.mailer.example, which does not align with shop.example. A pass on another domain does not count for DMARC.

Fix 1, plain: Nothing needs fixing. If you want both checks to match, give the service that sends this mail a custom return address on shop.example (often called a custom return path).

Fix 1, technical: Alignment comes from DKIM alone, which is enough. For SPF to align too, set a custom Return-Path domain under shop.example at the sending service.

Limit 1, plain: This page assumes the usual, looser domain match. A domain's DMARC setting can demand an exact match, and the headers don't show that setting.

Limit 1, technical: Alignment is computed in relaxed mode, the DMARC default, with strict mode beside it. adkim and aspf are set in the DMARC record, which is not in the headers.

Sender signals, plain: Yes, as far as the headers show.

Sender signals, technical: No flag fired: DMARC passed for shop.example, and the display name, Reply-To, and From domain raise nothing.

Spam signals, plain: These headers can't say. They carry no spam rating from the receiving system that this page can read.

Spam signals, technical: No spam filter result that this page can read was written by the receiver.

Signals, nothing fired, plain: Nothing in the headers points to forgery or spam. That covers the headers only, because this page doesn't judge the message text, links, or attachments.

Signals, nothing fired, technical: Nothing in the headers points to forgery or spam. That is a statement about the headers only: the body, links and attachments are not examined.

Signature check, plain: Checked today, November 13, 2026. What the recipient's email provider recorded when the message arrived is shown separately.

Signature check, technical: Checked November 13, 2026 from the message file. Each key was looked up over DNS over HTTPS at cloudflare-dns.com, and each signature was verified in this browser (RFC 6376 3.7). The results mx.receiver.example recorded at delivery are a separate fact and are not changed by this check.

Signature check label, plain: Checks out

Signature check, on arrival, plain: The recipient's email provider recorded that this signature passed when the message arrived.

Signature check, on arrival, technical: mx.receiver.example recorded dkim=pass for d=shop.example s=s1 at delivery.

Signature check, today, plain: The signature from shop.example matches the key published today. The message wasn't changed after it was signed.

Signature check, today, technical: DKIM d=shop.example s=s1 verifies: the rsa-sha256 signature over the header hash (c=relaxed/relaxed, 5 of the 5 names in h= present) checks against the 2048-bit RSA key at s1._domainkey.shop.example. The body hash matches bh=.

## signature check: checks out, key shorter than recommended

Plain headline: This message passed the sender check (DMARC). It was signed by shop.example, the domain in the From address.

Technical headline: DMARC at mx.receiver.example passed because DKIM d=shop.example s=s1 passed, and it aligns with the From domain shop.example (RFC5322.From).

Cause, plain: A message passes when it's signed by, or sent for, the domain in its From address, and this one was.

Cause, technical: For shop.example, the pass comes from aligned DKIM, which still passes after a forward if nothing alters the signed headers or body.

Policy, plain: The message passed, so the sender's DMARC setting didn't come into play.

Policy, technical: shop.example publishes p=reject, which asks for failing mail to be refused. This message passed, so the policy did not come into play.

Delivery, plain: Mail sent this way meets the rules Gmail, Yahoo, and Microsoft's Outlook.com set for proving who sent a message. Those rules also cover spam complaints and unsubscribe links, which the headers don't show.

Delivery, technical: SPF and DKIM both pass, and one aligns with the From domain shop.example, which publishes a DMARC record. That meets the authentication requirements for bulk senders. Google's Email sender guidelines, Yahoo's Sender Best Practices, and Microsoft's Outlook.com requirements for high volume senders all say so. Their spam rate and unsubscribe requirements are outside the headers.

Detail 1, plain: The message was signed by shop.example, which belongs to the sender.

Detail 1, technical: DKIM passed for d=shop.example s=s1, which aligns with shop.example.

Detail 2, plain: The sending server is approved, but by bounce.mailer.example, not by the sender's own domain.

Detail 2, technical: SPF passed for bounce.mailer.example, which does not align with shop.example. A pass on another domain does not count for DMARC.

Fix 1, plain: Nothing needs fixing. If you want both checks to match, give the service that sends this mail a custom return address on shop.example (often called a custom return path).

Fix 1, technical: Alignment comes from DKIM alone, which is enough. For SPF to align too, set a custom Return-Path domain under shop.example at the sending service.

Limit 1, plain: This page assumes the usual, looser domain match. A domain's DMARC setting can demand an exact match, and the headers don't show that setting.

Limit 1, technical: Alignment is computed in relaxed mode, the DMARC default, with strict mode beside it. adkim and aspf are set in the DMARC record, which is not in the headers.

Sender signals, plain: Yes, as far as the headers show.

Sender signals, technical: No flag fired: DMARC passed for shop.example, and the display name, Reply-To, and From domain raise nothing.

Spam signals, plain: These headers can't say. They carry no spam rating from the receiving system that this page can read.

Spam signals, technical: No spam filter result that this page can read was written by the receiver.

Signals, nothing fired, plain: Nothing in the headers points to forgery or spam. That covers the headers only, because this page doesn't judge the message text, links, or attachments.

Signals, nothing fired, technical: Nothing in the headers points to forgery or spam. That is a statement about the headers only: the body, links and attachments are not examined.

Signature check, plain: Checked today, November 13, 2026. What the recipient's email provider recorded when the message arrived is shown separately.

Signature check, technical: Checked November 13, 2026 from the message file. Each key was looked up over DNS over HTTPS at cloudflare-dns.com, and each signature was verified in this browser (RFC 6376 3.7). The results mx.receiver.example recorded at delivery are a separate fact and are not changed by this check.

Signature check label, plain: Checks out

Signature check, on arrival, plain: The recipient's email provider recorded that this signature passed when the message arrived.

Signature check, on arrival, technical: mx.receiver.example recorded dkim=pass for d=shop.example s=s1 at delivery.

Signature check, today, plain: The signature from shop.example matches the key published today. The message wasn't changed after it was signed.

Signature check, today, technical: DKIM d=shop.example s=s1 verifies: the rsa-sha256 signature over the header hash (c=relaxed/relaxed, 5 of the 5 names in h= present) checks against the 1024-bit RSA key at s1._domainkey.shop.example. The body hash matches bh=.

Signature check note 1, plain: The key works, but it's shorter than mail systems now recommend. Ask the service that sends this mail for a longer one.

Signature check note 1, technical: The RSA key at s1._domainkey.shop.example is 1024 bits. RFC 8301 3.2 says signers SHOULD use RSA keys of at least 2048 bits.

## signature check: checks out now, failed on arrival

Plain headline: This message failed the sender check (DMARC). The signature didn't check out and it came from a server that bounce.mailer.example allows. Nothing that checked out matches shop.example, the domain in the From address.

Technical headline: DMARC at mx.receiver.example failed because DKIM d=shop.example s=s1 failed verification and SPF passed for the Return-Path domain bounce.mailer.example (RFC5321.MailFrom), and nothing that passed aligns with the From domain shop.example (RFC5322.From).

Cause, plain: The message was changed after it was signed, or the signature doesn't match the sender's published key.

Cause, technical: The DKIM signature from shop.example did not verify at mx.receiver.example: something changed the signed part of the message after signing, or the key in DNS does not match. SPF passed only for bounce.mailer.example, which is not shop.example.

Policy, plain: shop.example's DMARC setting asks providers to refuse fake mail. The recipient's email provider refused this message.

Policy, technical: shop.example publishes p=reject, which asks for failing mail to be refused, and mx.receiver.example refused this message (dis=REJECT).

Delivery, plain: shop.example's DMARC setting asks mail providers to refuse mail that fails this way. Expect the ones that follow it to refuse every message with this problem.

Delivery, technical: The DMARC record of shop.example carries p=reject, which asks receivers to reject mail that fails DMARC (RFC 9989 4.7). Every message that fails this way falls under it. A receiver is not required to honor the request, so some copies may still arrive.

Detail 1, plain: The signature from shop.example didn't check out.

Detail 1, technical: DKIM failed for d=shop.example s=s1. Something changed the signed headers or body after signing, or the key in DNS does not match; the headers cannot show which.

Detail 2, plain: The sending server is approved, but by bounce.mailer.example, not by the sender's own domain.

Detail 2, technical: SPF passed for bounce.mailer.example, which does not align with shop.example. A pass on another domain does not count for DMARC.

Fix 1, plain: Ask whoever manages your mail whether anything adds a footer, a disclaimer, or tracking links after messages leave the service that sends this mail. That's the usual cause of a broken signature.

Fix 1, technical: The signature from d=shop.example broke between signing and mx.receiver.example. Look for anything that edits mail after the sending service signs it (a gateway, footer, disclaimer, or link rewriting), and check that the key at s1._domainkey.shop.example is the one it signs with.

Limit 1, plain: This page assumes the usual, looser domain match. A domain's DMARC setting can demand an exact match, and the headers don't show that setting.

Limit 1, technical: Alignment is computed in relaxed mode, the DMARC default, with strict mode beside it. adkim and aspf are set in the DMARC record, which is not in the headers.

Sender signals, plain: Maybe not. Treat this message with care.

Sender signals, technical: One signal says the author may not be who the From line shows.

Sender signal 1, plain: This message failed the sender check (DMARC), so nothing proves it came from shop.example.

Sender signal 1, technical: DMARC failed for the From domain shop.example (RFC5322.From), so no aligned SPF or DKIM pass vouches for the author domain.

Spam signals, plain: These headers can't say. They carry no spam rating from the receiving system that this page can read.

Spam signals, technical: No spam filter result that this page can read was written by the receiver.

Signature check, plain: Checked today, November 13, 2026. What the recipient's email provider recorded when the message arrived is shown separately.

Signature check, technical: Checked November 13, 2026 from the message file. Each key was looked up over DNS over HTTPS at cloudflare-dns.com, and each signature was verified in this browser (RFC 6376 3.7). The results mx.receiver.example recorded at delivery are a separate fact and are not changed by this check.

Signature check label, plain: Checks out today

Signature check, on arrival, plain: The recipient's email provider recorded that this signature failed when the message arrived.

Signature check, on arrival, technical: mx.receiver.example recorded dkim=fail for d=shop.example s=s1 at delivery.

Signature check, today, plain: The recipient's email provider recorded a failure when the message arrived, but this copy checks out today. This page can't show what was different then.

Signature check, today, technical: DKIM d=shop.example s=s1 verifies: the rsa-sha256 signature over the header hash (c=relaxed/relaxed, 5 of the 5 names in h= present) checks against the 2048-bit RSA key at s1._domainkey.shop.example. The body hash matches bh=. mx.receiver.example recorded dkim=fail at delivery. The key in DNS or the message it saw may have differed, and this page does not say which.

## signature check: text changed

Plain headline: This message failed the sender check (DMARC). The signature didn't check out and it came from a server that bounce.mailer.example allows. Nothing that checked out matches shop.example, the domain in the From address.

Technical headline: DMARC at mx.receiver.example failed because DKIM d=shop.example s=s1 failed verification and SPF passed for the Return-Path domain bounce.mailer.example (RFC5321.MailFrom), and nothing that passed aligns with the From domain shop.example (RFC5322.From).

Cause, plain: The signature from shop.example didn't check out when the message arrived. Checked today (November 13, 2026): The message text was changed after shop.example signed it, so the signature no longer matches. A forwarder, a mailing list, or a security filter that adds a footer or rewrites links can do that.

Cause, technical: The DKIM signature from shop.example did not verify at mx.receiver.example. Checked today (November 13, 2026): The rsa-sha256 signature over the header hash checks against the 2048-bit RSA key at s1._domainkey.shop.example, so the fields in h= and the key are intact. The body hash computed here, SyntheticComputedBh=, does not equal bh=. The body changed after signing (c=relaxed/relaxed, RFC 6376 3.7). SPF passed only for bounce.mailer.example, which is not shop.example.

Policy, plain: shop.example's DMARC setting asks providers to refuse fake mail. The recipient's email provider refused this message.

Policy, technical: shop.example publishes p=reject, which asks for failing mail to be refused, and mx.receiver.example refused this message (dis=REJECT).

Delivery, plain: shop.example's DMARC setting asks mail providers to refuse mail that fails this way. Expect the ones that follow it to refuse every message with this problem.

Delivery, technical: The DMARC record of shop.example carries p=reject, which asks receivers to reject mail that fails DMARC (RFC 9989 4.7). Every message that fails this way falls under it. A receiver is not required to honor the request, so some copies may still arrive.

Detail 1, plain: The signature from shop.example didn't check out. Checked today (November 13, 2026): The message text was changed after shop.example signed it, so the signature no longer matches. A forwarder, a mailing list, or a security filter that adds a footer or rewrites links can do that.

Detail 1, technical: DKIM failed for d=shop.example s=s1. Checked today (November 13, 2026): The rsa-sha256 signature over the header hash checks against the 2048-bit RSA key at s1._domainkey.shop.example, so the fields in h= and the key are intact. The body hash computed here, SyntheticComputedBh=, does not equal bh=. The body changed after signing (c=relaxed/relaxed, RFC 6376 3.7).

Detail 2, plain: The sending server is approved, but by bounce.mailer.example, not by the sender's own domain.

Detail 2, technical: SPF passed for bounce.mailer.example, which does not align with shop.example. A pass on another domain does not count for DMARC.

Fix 1, plain: Ask whoever manages your mail whether anything adds a footer, a disclaimer, or tracking links after messages leave the service that sends this mail.

Fix 1, technical: Look for anything that edits the body after the sending service signs it: a gateway footer, a disclaimer, or link rewriting.

Fix 2, plain: If the message came through a forward or a mailing list, the change happened there. Your own setup isn't the problem.

Fix 2, technical: If the message passed through a forwarder or a mailing list, the change happened there and nothing at shop.example needs fixing.

Fix 3, plain: Send a message straight to a mailbox, save it as a file, and check that copy here.

Fix 3, technical: Send a message straight to a mailbox with no forward and verify that copy from its file.

Limit 1, plain: This page assumes the usual, looser domain match. A domain's DMARC setting can demand an exact match, and the headers don't show that setting.

Limit 1, technical: Alignment is computed in relaxed mode, the DMARC default, with strict mode beside it. adkim and aspf are set in the DMARC record, which is not in the headers.

Sender signals, plain: Maybe not. Treat this message with care.

Sender signals, technical: One signal says the author may not be who the From line shows.

Sender signal 1, plain: This message failed the sender check (DMARC), so nothing proves it came from shop.example.

Sender signal 1, technical: DMARC failed for the From domain shop.example (RFC5322.From), so no aligned SPF or DKIM pass vouches for the author domain.

Spam signals, plain: These headers can't say. They carry no spam rating from the receiving system that this page can read.

Spam signals, technical: No spam filter result that this page can read was written by the receiver.

Signature check, plain: Checked today, November 13, 2026. What the recipient's email provider recorded when the message arrived is shown separately.

Signature check, technical: Checked November 13, 2026 from the message file. Each key was looked up over DNS over HTTPS at cloudflare-dns.com, and each signature was verified in this browser (RFC 6376 3.7). The results mx.receiver.example recorded at delivery are a separate fact and are not changed by this check.

Signature check label, plain: Cause found

Signature check, on arrival, plain: The recipient's email provider recorded that this signature failed when the message arrived.

Signature check, on arrival, technical: mx.receiver.example recorded dkim=fail for d=shop.example s=s1 at delivery.

Signature check, today, plain: The message text was changed after shop.example signed it, so the signature no longer matches. A forwarder, a mailing list, or a security filter that adds a footer or rewrites links can do that.

Signature check, today, technical: The rsa-sha256 signature over the header hash checks against the 2048-bit RSA key at s1._domainkey.shop.example, so the fields in h= and the key are intact. The body hash computed here, SyntheticComputedBh=, does not equal bh=. The body changed after signing (c=relaxed/relaxed, RFC 6376 3.7).

Signature check, who fixes it, plain: Whoever manages your mail can find what changed it.

Signature check, who fixes it, technical: Whoever runs the systems between the sending service and the mailbox.

Signature check step 1, plain: Ask whoever manages your mail whether anything adds a footer, a disclaimer, or tracking links after messages leave the service that sends this mail.

Signature check step 1, technical: Look for anything that edits the body after the sending service signs it: a gateway footer, a disclaimer, or link rewriting.

Signature check step 2, plain: If the message came through a forward or a mailing list, the change happened there. Your own setup isn't the problem.

Signature check step 2, technical: If the message passed through a forwarder or a mailing list, the change happened there and nothing at shop.example needs fixing.

Signature check step 3, plain: Send a message straight to a mailbox, save it as a file, and check that copy here.

Signature check step 3, technical: Send a message straight to a mailbox with no forward and verify that copy from its file.

## signature check: text not included

Plain headline: This message failed the sender check (DMARC). The signature didn't check out and it came from a server that bounce.mailer.example allows. Nothing that checked out matches shop.example, the domain in the From address.

Technical headline: DMARC at mx.receiver.example failed because DKIM d=shop.example s=s1 failed verification and SPF passed for the Return-Path domain bounce.mailer.example (RFC5321.MailFrom), and nothing that passed aligns with the From domain shop.example (RFC5322.From).

Cause, plain: The message was changed after it was signed, or the signature doesn't match the sender's published key.

Cause, technical: The DKIM signature from shop.example did not verify at mx.receiver.example: something changed the signed part of the message after signing, or the key in DNS does not match. SPF passed only for bounce.mailer.example, which is not shop.example.

Policy, plain: shop.example's DMARC setting asks providers to refuse fake mail. The recipient's email provider refused this message.

Policy, technical: shop.example publishes p=reject, which asks for failing mail to be refused, and mx.receiver.example refused this message (dis=REJECT).

Delivery, plain: shop.example's DMARC setting asks mail providers to refuse mail that fails this way. Expect the ones that follow it to refuse every message with this problem.

Delivery, technical: The DMARC record of shop.example carries p=reject, which asks receivers to reject mail that fails DMARC (RFC 9989 4.7). Every message that fails this way falls under it. A receiver is not required to honor the request, so some copies may still arrive.

Detail 1, plain: The signature from shop.example didn't check out.

Detail 1, technical: DKIM failed for d=shop.example s=s1. Something changed the signed headers or body after signing, or the key in DNS does not match; the headers cannot show which.

Detail 2, plain: The sending server is approved, but by bounce.mailer.example, not by the sender's own domain.

Detail 2, technical: SPF passed for bounce.mailer.example, which does not align with shop.example. A pass on another domain does not count for DMARC.

Fix 1, plain: Ask whoever manages your mail whether anything adds a footer, a disclaimer, or tracking links after messages leave the service that sends this mail. That's the usual cause of a broken signature.

Fix 1, technical: The signature from d=shop.example broke between signing and mx.receiver.example. Look for anything that edits mail after the sending service signs it (a gateway, footer, disclaimer, or link rewriting), and check that the key at s1._domainkey.shop.example is the one it signs with.

Limit 1, plain: This page assumes the usual, looser domain match. A domain's DMARC setting can demand an exact match, and the headers don't show that setting.

Limit 1, technical: Alignment is computed in relaxed mode, the DMARC default, with strict mode beside it. adkim and aspf are set in the DMARC record, which is not in the headers.

Sender signals, plain: Maybe not. Treat this message with care.

Sender signals, technical: One signal says the author may not be who the From line shows.

Sender signal 1, plain: This message failed the sender check (DMARC), so nothing proves it came from shop.example.

Sender signal 1, technical: DMARC failed for the From domain shop.example (RFC5322.From), so no aligned SPF or DKIM pass vouches for the author domain.

Spam signals, plain: These headers can't say. They carry no spam rating from the receiving system that this page can read.

Spam signals, technical: No spam filter result that this page can read was written by the receiver.

Signature check, plain: Checked today, November 13, 2026. What the recipient's email provider recorded when the message arrived is shown separately.

Signature check, technical: Checked November 13, 2026 from the pasted text. Each key was looked up over DNS over HTTPS at cloudflare-dns.com, and each signature was verified in this browser (RFC 6376 3.7). The results mx.receiver.example recorded at delivery are a separate fact and are not changed by this check.

Signature check label, plain: Partly checked

Signature check, on arrival, plain: The recipient's email provider recorded that this signature failed when the message arrived.

Signature check, on arrival, technical: mx.receiver.example recorded dkim=fail for d=shop.example s=s1 at delivery.

Signature check, today, plain: The signed details at the top of the message are intact and the key matches. The message text wasn't included, so it couldn't be checked. Drop the whole message file on the box to check it.

Signature check, today, technical: The rsa-sha256 signature over the header hash (c=relaxed/relaxed) checks against the 2048-bit RSA key at s1._domainkey.shop.example, so the fields in h= and the key are intact. No body followed the headers, so bh= was not compared.

## signature check: file too large for the text

Plain headline: This message failed the sender check (DMARC). The signature didn't check out and it came from a server that bounce.mailer.example allows. Nothing that checked out matches shop.example, the domain in the From address.

Technical headline: DMARC at mx.receiver.example failed because DKIM d=shop.example s=s1 failed verification and SPF passed for the Return-Path domain bounce.mailer.example (RFC5321.MailFrom), and nothing that passed aligns with the From domain shop.example (RFC5322.From).

Cause, plain: The message was changed after it was signed, or the signature doesn't match the sender's published key.

Cause, technical: The DKIM signature from shop.example did not verify at mx.receiver.example: something changed the signed part of the message after signing, or the key in DNS does not match. SPF passed only for bounce.mailer.example, which is not shop.example.

Policy, plain: shop.example's DMARC setting asks providers to refuse fake mail. The recipient's email provider refused this message.

Policy, technical: shop.example publishes p=reject, which asks for failing mail to be refused, and mx.receiver.example refused this message (dis=REJECT).

Delivery, plain: shop.example's DMARC setting asks mail providers to refuse mail that fails this way. Expect the ones that follow it to refuse every message with this problem.

Delivery, technical: The DMARC record of shop.example carries p=reject, which asks receivers to reject mail that fails DMARC (RFC 9989 4.7). Every message that fails this way falls under it. A receiver is not required to honor the request, so some copies may still arrive.

Detail 1, plain: The signature from shop.example didn't check out.

Detail 1, technical: DKIM failed for d=shop.example s=s1. Something changed the signed headers or body after signing, or the key in DNS does not match; the headers cannot show which.

Detail 2, plain: The sending server is approved, but by bounce.mailer.example, not by the sender's own domain.

Detail 2, technical: SPF passed for bounce.mailer.example, which does not align with shop.example. A pass on another domain does not count for DMARC.

Fix 1, plain: Ask whoever manages your mail whether anything adds a footer, a disclaimer, or tracking links after messages leave the service that sends this mail. That's the usual cause of a broken signature.

Fix 1, technical: The signature from d=shop.example broke between signing and mx.receiver.example. Look for anything that edits mail after the sending service signs it (a gateway, footer, disclaimer, or link rewriting), and check that the key at s1._domainkey.shop.example is the one it signs with.

Limit 1, plain: This page assumes the usual, looser domain match. A domain's DMARC setting can demand an exact match, and the headers don't show that setting.

Limit 1, technical: Alignment is computed in relaxed mode, the DMARC default, with strict mode beside it. adkim and aspf are set in the DMARC record, which is not in the headers.

Sender signals, plain: Maybe not. Treat this message with care.

Sender signals, technical: One signal says the author may not be who the From line shows.

Sender signal 1, plain: This message failed the sender check (DMARC), so nothing proves it came from shop.example.

Sender signal 1, technical: DMARC failed for the From domain shop.example (RFC5322.From), so no aligned SPF or DKIM pass vouches for the author domain.

Spam signals, plain: These headers can't say. They carry no spam rating from the receiving system that this page can read.

Spam signals, technical: No spam filter result that this page can read was written by the receiver.

Signature check, plain: Checked today, November 13, 2026. What the recipient's email provider recorded when the message arrived is shown separately.

Signature check, technical: Checked November 13, 2026 from the message file. Each key was looked up over DNS over HTTPS at cloudflare-dns.com, and each signature was verified in this browser (RFC 6376 3.7). The results mx.receiver.example recorded at delivery are a separate fact and are not changed by this check.

Signature check label, plain: Partly checked

Signature check, on arrival, plain: The recipient's email provider recorded that this signature failed when the message arrived.

Signature check, on arrival, technical: mx.receiver.example recorded dkim=fail for d=shop.example s=s1 at delivery.

Signature check, today, plain: The signed details at the top of the message are intact and the key matches. The message file is larger than this page reads, so the message text couldn't be checked.

Signature check, today, technical: The rsa-sha256 signature over the header hash (c=relaxed/relaxed) checks against the 2048-bit RSA key at s1._domainkey.shop.example, so the fields in h= and the key are intact. The file is larger than this page reads, so bh= was not compared.

## signature check: signed detail changed

Plain headline: This message failed the sender check (DMARC). The signature didn't check out and it came from a server that bounce.mailer.example allows. Nothing that checked out matches shop.example, the domain in the From address.

Technical headline: DMARC at mx.receiver.example failed because DKIM d=shop.example s=s1 failed verification and SPF passed for the Return-Path domain bounce.mailer.example (RFC5321.MailFrom), and nothing that passed aligns with the From domain shop.example (RFC5322.From).

Cause, plain: The signature from shop.example didn't check out when the message arrived. Checked today (November 13, 2026): A signed detail, such as the subject or the From line, was changed after shop.example signed the message. Something between the sender and the mailbox edited the message.

Cause, technical: The DKIM signature from shop.example did not verify at mx.receiver.example. Checked today (November 13, 2026): The RSA public key operation with the 2048-bit RSA key at s1._domainkey.shop.example yields valid PKCS #1 v1.5 padding (RFC 8017 9.2) around a different SHA-256 hash. The key is the one that signed, and a field listed in h=, or the DKIM-Signature field itself, changed after signing (c=relaxed/relaxed). The body hash matches bh=. SPF passed only for bounce.mailer.example, which is not shop.example.

Policy, plain: shop.example's DMARC setting asks providers to refuse fake mail. The recipient's email provider refused this message.

Policy, technical: shop.example publishes p=reject, which asks for failing mail to be refused, and mx.receiver.example refused this message (dis=REJECT).

Delivery, plain: shop.example's DMARC setting asks mail providers to refuse mail that fails this way. Expect the ones that follow it to refuse every message with this problem.

Delivery, technical: The DMARC record of shop.example carries p=reject, which asks receivers to reject mail that fails DMARC (RFC 9989 4.7). Every message that fails this way falls under it. A receiver is not required to honor the request, so some copies may still arrive.

Detail 1, plain: The signature from shop.example didn't check out. Checked today (November 13, 2026): A signed detail, such as the subject or the From line, was changed after shop.example signed the message. Something between the sender and the mailbox edited the message.

Detail 1, technical: DKIM failed for d=shop.example s=s1. Checked today (November 13, 2026): The RSA public key operation with the 2048-bit RSA key at s1._domainkey.shop.example yields valid PKCS #1 v1.5 padding (RFC 8017 9.2) around a different SHA-256 hash. The key is the one that signed, and a field listed in h=, or the DKIM-Signature field itself, changed after signing (c=relaxed/relaxed). The body hash matches bh=.

Detail 2, plain: The sending server is approved, but by bounce.mailer.example, not by the sender's own domain.

Detail 2, technical: SPF passed for bounce.mailer.example, which does not align with shop.example. A pass on another domain does not count for DMARC.

Fix 1, plain: Ask whoever manages your mail whether anything changes the subject or the From line after messages leave the service that sends this mail, such as a tag added to the subject.

Fix 1, technical: Look for anything that rewrites a field in h= after the sending service signs it, such as a subject tag or a From rewrite.

Fix 2, plain: If the message came through a forward or a mailing list, the change happened there. Your own setup isn't the problem.

Fix 2, technical: If the message passed through a forwarder or a mailing list, the change happened there and nothing at shop.example needs fixing.

Fix 3, plain: Send a message straight to a mailbox, save it as a file, and check that copy here.

Fix 3, technical: Send a message straight to a mailbox with no forward and verify that copy from its file.

Limit 1, plain: This page assumes the usual, looser domain match. A domain's DMARC setting can demand an exact match, and the headers don't show that setting.

Limit 1, technical: Alignment is computed in relaxed mode, the DMARC default, with strict mode beside it. adkim and aspf are set in the DMARC record, which is not in the headers.

Sender signals, plain: Maybe not. Treat this message with care.

Sender signals, technical: One signal says the author may not be who the From line shows.

Sender signal 1, plain: This message failed the sender check (DMARC), so nothing proves it came from shop.example.

Sender signal 1, technical: DMARC failed for the From domain shop.example (RFC5322.From), so no aligned SPF or DKIM pass vouches for the author domain.

Spam signals, plain: These headers can't say. They carry no spam rating from the receiving system that this page can read.

Spam signals, technical: No spam filter result that this page can read was written by the receiver.

Signature check, plain: Checked today, November 13, 2026. What the recipient's email provider recorded when the message arrived is shown separately.

Signature check, technical: Checked November 13, 2026 from the message file. Each key was looked up over DNS over HTTPS at cloudflare-dns.com, and each signature was verified in this browser (RFC 6376 3.7). The results mx.receiver.example recorded at delivery are a separate fact and are not changed by this check.

Signature check label, plain: Cause found

Signature check, on arrival, plain: The recipient's email provider recorded that this signature failed when the message arrived.

Signature check, on arrival, technical: mx.receiver.example recorded dkim=fail for d=shop.example s=s1 at delivery.

Signature check, today, plain: A signed detail, such as the subject or the From line, was changed after shop.example signed the message. Something between the sender and the mailbox edited the message.

Signature check, today, technical: The RSA public key operation with the 2048-bit RSA key at s1._domainkey.shop.example yields valid PKCS #1 v1.5 padding (RFC 8017 9.2) around a different SHA-256 hash. The key is the one that signed, and a field listed in h=, or the DKIM-Signature field itself, changed after signing (c=relaxed/relaxed). The body hash matches bh=.

Signature check, who fixes it, plain: Whoever manages your mail can find what changed it.

Signature check, who fixes it, technical: Whoever runs the systems between the sending service and the mailbox.

Signature check step 1, plain: Ask whoever manages your mail whether anything changes the subject or the From line after messages leave the service that sends this mail, such as a tag added to the subject.

Signature check step 1, technical: Look for anything that rewrites a field in h= after the sending service signs it, such as a subject tag or a From rewrite.

Signature check step 2, plain: If the message came through a forward or a mailing list, the change happened there. Your own setup isn't the problem.

Signature check step 2, technical: If the message passed through a forwarder or a mailing list, the change happened there and nothing at shop.example needs fixing.

Signature check step 3, plain: Send a message straight to a mailbox, save it as a file, and check that copy here.

Signature check step 3, technical: Send a message straight to a mailbox with no forward and verify that copy from its file.

## signature check: wrong key

Plain headline: This message failed the sender check (DMARC). The signature didn't check out and it came from a server that bounce.mailer.example allows. Nothing that checked out matches shop.example, the domain in the From address.

Technical headline: DMARC at mx.receiver.example failed because DKIM d=shop.example s=s1 failed verification and SPF passed for the Return-Path domain bounce.mailer.example (RFC5321.MailFrom), and nothing that passed aligns with the From domain shop.example (RFC5322.From).

Cause, plain: The signature from shop.example didn't check out when the message arrived. Checked today (November 13, 2026): The published key (DKIM key) for shop.example isn't the one that signed this message. Ask the service that sends this mail for its current DNS setting and compare the two.

Cause, technical: The DKIM signature from shop.example did not verify at mx.receiver.example. Checked today (November 13, 2026): The RSA public key operation with the 2048-bit RSA key at s1._domainkey.shop.example does not yield PKCS #1 v1.5 padding (RFC 8017 9.2), so that key did not produce this b= value. The key in DNS is not the key that signed. SPF passed only for bounce.mailer.example, which is not shop.example.

Policy, plain: shop.example's DMARC setting asks providers to refuse fake mail. The recipient's email provider refused this message.

Policy, technical: shop.example publishes p=reject, which asks for failing mail to be refused, and mx.receiver.example refused this message (dis=REJECT).

Delivery, plain: shop.example's DMARC setting asks mail providers to refuse mail that fails this way. Expect the ones that follow it to refuse every message with this problem.

Delivery, technical: The DMARC record of shop.example carries p=reject, which asks receivers to reject mail that fails DMARC (RFC 9989 4.7). Every message that fails this way falls under it. A receiver is not required to honor the request, so some copies may still arrive.

Detail 1, plain: The signature from shop.example didn't check out. Checked today (November 13, 2026): The published key (DKIM key) for shop.example isn't the one that signed this message. Ask the service that sends this mail for its current DNS setting and compare the two.

Detail 1, technical: DKIM failed for d=shop.example s=s1. Checked today (November 13, 2026): The RSA public key operation with the 2048-bit RSA key at s1._domainkey.shop.example does not yield PKCS #1 v1.5 padding (RFC 8017 9.2), so that key did not produce this b= value. The key in DNS is not the key that signed.

Detail 2, plain: The sending server is approved, but by bounce.mailer.example, not by the sender's own domain.

Detail 2, technical: SPF passed for bounce.mailer.example, which does not align with shop.example. A pass on another domain does not count for DMARC.

Fix 1, plain: Ask the service that sends this mail for its current DKIM setting for shop.example.

Fix 1, technical: Get the key the sending service signs selector s1 with now.

Fix 2, plain: Ask whoever manages the DNS for shop.example to compare it with the DNS setting for shop.example, and to replace the value if they differ.

Fix 2, technical: Compare its p= with the record at s1._domainkey.shop.example and replace the stale one. A key rotated after this message was sent gives the same result.

Fix 3, plain: Send a new message and check that one here.

Fix 3, technical: Send a new message and verify it again. Receivers that already judged this one keep their result.

Limit 1, plain: This page assumes the usual, looser domain match. A domain's DMARC setting can demand an exact match, and the headers don't show that setting.

Limit 1, technical: Alignment is computed in relaxed mode, the DMARC default, with strict mode beside it. adkim and aspf are set in the DMARC record, which is not in the headers.

Sender signals, plain: Maybe not. Treat this message with care.

Sender signals, technical: One signal says the author may not be who the From line shows.

Sender signal 1, plain: This message failed the sender check (DMARC), so nothing proves it came from shop.example.

Sender signal 1, technical: DMARC failed for the From domain shop.example (RFC5322.From), so no aligned SPF or DKIM pass vouches for the author domain.

Spam signals, plain: These headers can't say. They carry no spam rating from the receiving system that this page can read.

Spam signals, technical: No spam filter result that this page can read was written by the receiver.

Signature check, plain: Checked today, November 13, 2026. What the recipient's email provider recorded when the message arrived is shown separately.

Signature check, technical: Checked November 13, 2026 from the message file. Each key was looked up over DNS over HTTPS at cloudflare-dns.com, and each signature was verified in this browser (RFC 6376 3.7). The results mx.receiver.example recorded at delivery are a separate fact and are not changed by this check.

Signature check label, plain: Cause found

Signature check, on arrival, plain: The recipient's email provider recorded that this signature failed when the message arrived.

Signature check, on arrival, technical: mx.receiver.example recorded dkim=fail for d=shop.example s=s1 at delivery.

Signature check, today, plain: The published key (DKIM key) for shop.example isn't the one that signed this message. Ask the service that sends this mail for its current DNS setting and compare the two.

Signature check, today, technical: The RSA public key operation with the 2048-bit RSA key at s1._domainkey.shop.example does not yield PKCS #1 v1.5 padding (RFC 8017 9.2), so that key did not produce this b= value. The key in DNS is not the key that signed.

Signature check, who fixes it, plain: Whoever manages the DNS for shop.example fixes this, with the setting from the service that sends this mail.

Signature check, who fixes it, technical: Whoever manages the DNS for shop.example publishes the record, and the sending service supplies it.

Signature check step 1, plain: Ask the service that sends this mail for its current DKIM setting for shop.example.

Signature check step 1, technical: Get the key the sending service signs selector s1 with now.

Signature check step 2, plain: Ask whoever manages the DNS for shop.example to compare it with the DNS setting for shop.example, and to replace the value if they differ.

Signature check step 2, technical: Compare its p= with the record at s1._domainkey.shop.example and replace the stale one. A key rotated after this message was sent gives the same result.

Signature check step 3, plain: Send a new message and check that one here.

Signature check step 3, technical: Send a new message and verify it again. Receivers that already judged this one keep their result.

## signature check: cannot tell which (Ed25519)

Plain headline: This message failed the sender check (DMARC). The signature didn't check out and it came from a server that bounce.mailer.example allows. Nothing that checked out matches shop.example, the domain in the From address.

Technical headline: DMARC at mx.receiver.example failed because DKIM d=shop.example s=s1 failed verification and SPF passed for the Return-Path domain bounce.mailer.example (RFC5321.MailFrom), and nothing that passed aligns with the From domain shop.example (RFC5322.From).

Cause, plain: The signature from shop.example didn't check out when the message arrived. Checked today (November 13, 2026): The signature from shop.example doesn't match. For this kind of signature the page can't tell whether the message changed or the key is wrong.

Cause, technical: The DKIM signature from shop.example did not verify at mx.receiver.example. Checked today (November 13, 2026): The ed25519-sha256 signature (RFC 8463) does not verify against the key at s1._domainkey.shop.example. An Ed25519 failure does not show whether the signed data changed or the key differs. The body hash matches bh=. SPF passed only for bounce.mailer.example, which is not shop.example.

Policy, plain: shop.example's DMARC setting asks providers to refuse fake mail. The recipient's email provider refused this message.

Policy, technical: shop.example publishes p=reject, which asks for failing mail to be refused, and mx.receiver.example refused this message (dis=REJECT).

Delivery, plain: shop.example's DMARC setting asks mail providers to refuse mail that fails this way. Expect the ones that follow it to refuse every message with this problem.

Delivery, technical: The DMARC record of shop.example carries p=reject, which asks receivers to reject mail that fails DMARC (RFC 9989 4.7). Every message that fails this way falls under it. A receiver is not required to honor the request, so some copies may still arrive.

Detail 1, plain: The signature from shop.example didn't check out. Checked today (November 13, 2026): The signature from shop.example doesn't match. For this kind of signature the page can't tell whether the message changed or the key is wrong.

Detail 1, technical: DKIM failed for d=shop.example s=s1. Checked today (November 13, 2026): The ed25519-sha256 signature (RFC 8463) does not verify against the key at s1._domainkey.shop.example. An Ed25519 failure does not show whether the signed data changed or the key differs. The body hash matches bh=.

Detail 2, plain: The sending server is approved, but by bounce.mailer.example, not by the sender's own domain.

Detail 2, technical: SPF passed for bounce.mailer.example, which does not align with shop.example. A pass on another domain does not count for DMARC.

Fix 1, plain: Ask the service that sends this mail for its current DKIM setting for shop.example, and compare it with the DNS setting.

Fix 1, technical: Compare the p= at s1._domainkey.shop.example with the key the sending service signs with.

Fix 2, plain: If they match, ask whoever manages your mail whether anything changes messages after they are sent.

Fix 2, technical: If they match, look for anything that edits the message after signing.

Limit 1, plain: This page assumes the usual, looser domain match. A domain's DMARC setting can demand an exact match, and the headers don't show that setting.

Limit 1, technical: Alignment is computed in relaxed mode, the DMARC default, with strict mode beside it. adkim and aspf are set in the DMARC record, which is not in the headers.

Sender signals, plain: Maybe not. Treat this message with care.

Sender signals, technical: One signal says the author may not be who the From line shows.

Sender signal 1, plain: This message failed the sender check (DMARC), so nothing proves it came from shop.example.

Sender signal 1, technical: DMARC failed for the From domain shop.example (RFC5322.From), so no aligned SPF or DKIM pass vouches for the author domain.

Spam signals, plain: These headers can't say. They carry no spam rating from the receiving system that this page can read.

Spam signals, technical: No spam filter result that this page can read was written by the receiver.

Signature check, plain: Checked today, November 13, 2026. What the recipient's email provider recorded when the message arrived is shown separately.

Signature check, technical: Checked November 13, 2026 from the message file. Each key was looked up over DNS over HTTPS at cloudflare-dns.com, and each signature was verified in this browser (RFC 6376 3.7). The results mx.receiver.example recorded at delivery are a separate fact and are not changed by this check.

Signature check label, plain: Cause found

Signature check, on arrival, plain: The recipient's email provider recorded that this signature failed when the message arrived.

Signature check, on arrival, technical: mx.receiver.example recorded dkim=fail for d=shop.example s=s1 at delivery.

Signature check, today, plain: The signature from shop.example doesn't match. For this kind of signature the page can't tell whether the message changed or the key is wrong.

Signature check, today, technical: The ed25519-sha256 signature (RFC 8463) does not verify against the key at s1._domainkey.shop.example. An Ed25519 failure does not show whether the signed data changed or the key differs. The body hash matches bh=.

Signature check, who fixes it, plain: Start with the service that sends this mail.

Signature check, who fixes it, technical: Start with the key, then the path.

Signature check step 1, plain: Ask the service that sends this mail for its current DKIM setting for shop.example, and compare it with the DNS setting.

Signature check step 1, technical: Compare the p= at s1._domainkey.shop.example with the key the sending service signs with.

Signature check step 2, plain: If they match, ask whoever manages your mail whether anything changes messages after they are sent.

Signature check step 2, technical: If they match, look for anything that edits the message after signing.

## signature check: pasted text

Plain headline: This message failed the sender check (DMARC). The signature didn't check out and it came from a server that bounce.mailer.example allows. Nothing that checked out matches shop.example, the domain in the From address.

Technical headline: DMARC at mx.receiver.example failed because DKIM d=shop.example s=s1 failed verification and SPF passed for the Return-Path domain bounce.mailer.example (RFC5321.MailFrom), and nothing that passed aligns with the From domain shop.example (RFC5322.From).

Cause, plain: The message was changed after it was signed, or the signature doesn't match the sender's published key.

Cause, technical: The DKIM signature from shop.example did not verify at mx.receiver.example: something changed the signed part of the message after signing, or the key in DNS does not match. SPF passed only for bounce.mailer.example, which is not shop.example.

Policy, plain: shop.example's DMARC setting asks providers to refuse fake mail. The recipient's email provider refused this message.

Policy, technical: shop.example publishes p=reject, which asks for failing mail to be refused, and mx.receiver.example refused this message (dis=REJECT).

Delivery, plain: shop.example's DMARC setting asks mail providers to refuse mail that fails this way. Expect the ones that follow it to refuse every message with this problem.

Delivery, technical: The DMARC record of shop.example carries p=reject, which asks receivers to reject mail that fails DMARC (RFC 9989 4.7). Every message that fails this way falls under it. A receiver is not required to honor the request, so some copies may still arrive.

Detail 1, plain: The signature from shop.example didn't check out.

Detail 1, technical: DKIM failed for d=shop.example s=s1. Something changed the signed headers or body after signing, or the key in DNS does not match; the headers cannot show which.

Detail 2, plain: The sending server is approved, but by bounce.mailer.example, not by the sender's own domain.

Detail 2, technical: SPF passed for bounce.mailer.example, which does not align with shop.example. A pass on another domain does not count for DMARC.

Fix 1, plain: Ask whoever manages your mail whether anything adds a footer, a disclaimer, or tracking links after messages leave the service that sends this mail. That's the usual cause of a broken signature.

Fix 1, technical: The signature from d=shop.example broke between signing and mx.receiver.example. Look for anything that edits mail after the sending service signs it (a gateway, footer, disclaimer, or link rewriting), and check that the key at s1._domainkey.shop.example is the one it signs with.

Limit 1, plain: This page assumes the usual, looser domain match. A domain's DMARC setting can demand an exact match, and the headers don't show that setting.

Limit 1, technical: Alignment is computed in relaxed mode, the DMARC default, with strict mode beside it. adkim and aspf are set in the DMARC record, which is not in the headers.

Sender signals, plain: Maybe not. Treat this message with care.

Sender signals, technical: One signal says the author may not be who the From line shows.

Sender signal 1, plain: This message failed the sender check (DMARC), so nothing proves it came from shop.example.

Sender signal 1, technical: DMARC failed for the From domain shop.example (RFC5322.From), so no aligned SPF or DKIM pass vouches for the author domain.

Spam signals, plain: These headers can't say. They carry no spam rating from the receiving system that this page can read.

Spam signals, technical: No spam filter result that this page can read was written by the receiver.

Signature check, plain: Checked today, November 13, 2026. What the recipient's email provider recorded when the message arrived is shown separately.

Signature check, technical: Checked November 13, 2026 from the pasted text. Each key was looked up over DNS over HTTPS at cloudflare-dns.com, and each signature was verified in this browser (RFC 6376 3.7). The results mx.receiver.example recorded at delivery are a separate fact and are not changed by this check.

Signature check label, plain: Could not confirm

Signature check, on arrival, plain: The recipient's email provider recorded that this signature failed when the message arrived.

Signature check, on arrival, technical: mx.receiver.example recorded dkim=fail for d=shop.example s=s1 at delivery.

Signature check, today, plain: Copying can change spaces, so this check couldn't confirm the signature from pasted text. Drop the message file on the box for a firm answer.

Signature check, today, technical: Verification from pasted text did not succeed, which a paste can cause by itself: copying can change the whitespace and line folds the canonicalization covers. Seen here: The RSA public key operation with the 2048-bit RSA key at s1._domainkey.shop.example yields valid PKCS #1 v1.5 padding (RFC 8017 9.2) around a different SHA-256 hash. The key is the one that signed, and a field listed in h=, or the DKIM-Signature field itself, changed after signing (c=relaxed/relaxed). The body hash matches bh=. Only the message file gives a firm result.

## signature check: passed on arrival, fails today

Plain headline: This message passed the sender check (DMARC). It was signed by shop.example, the domain in the From address.

Technical headline: DMARC at mx.receiver.example passed because DKIM d=shop.example s=s1 passed, and it aligns with the From domain shop.example (RFC5322.From).

Cause, plain: A message passes when it's signed by, or sent for, the domain in its From address, and this one was.

Cause, technical: For shop.example, the pass comes from aligned DKIM, which still passes after a forward if nothing alters the signed headers or body.

Policy, plain: The message passed, so the sender's DMARC setting didn't come into play.

Policy, technical: shop.example publishes p=reject, which asks for failing mail to be refused. This message passed, so the policy did not come into play.

Delivery, plain: Mail sent this way meets the rules Gmail, Yahoo, and Microsoft's Outlook.com set for proving who sent a message. Those rules also cover spam complaints and unsubscribe links, which the headers don't show.

Delivery, technical: SPF and DKIM both pass, and one aligns with the From domain shop.example, which publishes a DMARC record. That meets the authentication requirements for bulk senders. Google's Email sender guidelines, Yahoo's Sender Best Practices, and Microsoft's Outlook.com requirements for high volume senders all say so. Their spam rate and unsubscribe requirements are outside the headers.

Detail 1, plain: The message was signed by shop.example, which belongs to the sender.

Detail 1, technical: DKIM passed for d=shop.example s=s1, which aligns with shop.example.

Detail 2, plain: The sending server is approved, but by bounce.mailer.example, not by the sender's own domain.

Detail 2, technical: SPF passed for bounce.mailer.example, which does not align with shop.example. A pass on another domain does not count for DMARC.

Fix 1, plain: Nothing needs fixing. If you want both checks to match, give the service that sends this mail a custom return address on shop.example (often called a custom return path).

Fix 1, technical: Alignment comes from DKIM alone, which is enough. For SPF to align too, set a custom Return-Path domain under shop.example at the sending service.

Limit 1, plain: This page assumes the usual, looser domain match. A domain's DMARC setting can demand an exact match, and the headers don't show that setting.

Limit 1, technical: Alignment is computed in relaxed mode, the DMARC default, with strict mode beside it. adkim and aspf are set in the DMARC record, which is not in the headers.

Sender signals, plain: Yes, as far as the headers show.

Sender signals, technical: No flag fired: DMARC passed for shop.example, and the display name, Reply-To, and From domain raise nothing.

Spam signals, plain: These headers can't say. They carry no spam rating from the receiving system that this page can read.

Spam signals, technical: No spam filter result that this page can read was written by the receiver.

Signals, nothing fired, plain: Nothing in the headers points to forgery or spam. That covers the headers only, because this page doesn't judge the message text, links, or attachments.

Signals, nothing fired, technical: Nothing in the headers points to forgery or spam. That is a statement about the headers only: the body, links and attachments are not examined.

Signature check, plain: Checked today, November 13, 2026. What the recipient's email provider recorded when the message arrived is shown separately.

Signature check, technical: Checked November 13, 2026 from the message file. Each key was looked up over DNS over HTTPS at cloudflare-dns.com, and each signature was verified in this browser (RFC 6376 3.7). The results mx.receiver.example recorded at delivery are a separate fact and are not changed by this check.

Signature check label, plain: Doesn't check out today

Signature check, on arrival, plain: The recipient's email provider recorded that this signature passed when the message arrived.

Signature check, on arrival, technical: mx.receiver.example recorded dkim=pass for d=shop.example s=s1 at delivery.

Signature check, today, plain: The recipient's email provider recorded that this signature passed when the message arrived, but it doesn't check out today. This page can't show what changed since then.

Signature check, today, technical: mx.receiver.example recorded dkim=pass at delivery. Seen today: The RSA public key operation with the 2048-bit RSA key at s1._domainkey.shop.example does not yield PKCS #1 v1.5 padding (RFC 8017 9.2), so that key did not produce this b= value. The key in DNS is not the key that signed. The key in DNS or this copy may differ from what the receiver saw, and this page does not say which.

## signature check: rsa-sha1 is not checked

Plain headline: This message passed the sender check (DMARC). It was signed by shop.example with an outdated method (rsa-sha1) that mail systems should no longer accept. That matches shop.example, the domain in the From address.

Technical headline: DMARC at mx.receiver.example passed because DKIM d=shop.example s=s1 passed (a=rsa-sha1, which RFC 8301 3.1 says verifiers must treat as failed), and it aligns with the From domain shop.example (RFC5322.From).

Cause, plain: A message passes when it's signed by, or sent for, the domain in its From address, and this one was. But the signature uses an outdated method (rsa-sha1), so mail systems that follow current rules would fail it.

Cause, technical: For shop.example, the pass comes from aligned DKIM, which still passes after a forward if nothing alters the signed headers or body. The signature uses rsa-sha1, which RFC 8301 3.1 has verifiers treat as failed, so receivers that follow it would fail this message.

Policy, plain: The message passed, so the sender's DMARC setting didn't come into play.

Policy, technical: shop.example publishes p=reject, which asks for failing mail to be refused. This message passed, so the policy did not come into play.

Delivery, plain: At mail providers that no longer accept the old method, this mail fails the sender check (DMARC). shop.example's DMARC setting then asks them to refuse it.

Delivery, technical: A verifier that follows RFC 8301 3.1 does not count this signature. Nothing else aligns with shop.example, so DMARC fails there, and the DMARC record of shop.example carries p=reject, which asks receivers to reject failing mail (RFC 9989 4.7).

Detail 1, plain: The message was signed by shop.example, but with an outdated method (rsa-sha1) that mail systems should no longer accept.

Detail 1, technical: DKIM passed for d=shop.example s=s1, which aligns with shop.example, but the signature uses rsa-sha1. RFC 8301 3.1 says verifiers must not accept rsa-sha1, so a receiver that follows it would not count this pass.

Detail 2, plain: The sending server is approved, but by bounce.mailer.example, not by the sender's own domain.

Detail 2, technical: SPF passed for bounce.mailer.example, which does not align with shop.example. A pass on another domain does not count for DMARC.

Fix 1, plain: Ask the service that sends this mail to sign with the current method (rsa-sha256). This message uses an old one (rsa-sha1) that mail systems following current rules no longer accept, so it may fail elsewhere.

Fix 1, technical: Sign with rsa-sha256 at the sending service instead of rsa-sha1 for d=shop.example. RFC 8301 3.1 has verifiers treat rsa-sha1 as failed, so this pass may not hold at other receivers.

Fix 2, plain: Nothing needs fixing. If you want both checks to match, give the service that sends this mail a custom return address on shop.example (often called a custom return path).

Fix 2, technical: Alignment comes from DKIM alone, which is enough. For SPF to align too, set a custom Return-Path domain under shop.example at the sending service.

Limit 1, plain: This page assumes the usual, looser domain match. A domain's DMARC setting can demand an exact match, and the headers don't show that setting.

Limit 1, technical: Alignment is computed in relaxed mode, the DMARC default, with strict mode beside it. adkim and aspf are set in the DMARC record, which is not in the headers.

Sender signals, plain: Yes, as far as the headers show.

Sender signals, technical: No flag fired: DMARC passed for shop.example, and the display name, Reply-To, and From domain raise nothing.

Spam signals, plain: These headers can't say. They carry no spam rating from the receiving system that this page can read.

Spam signals, technical: No spam filter result that this page can read was written by the receiver.

Signals, nothing fired, plain: Nothing in the headers points to forgery or spam. That covers the headers only, because this page doesn't judge the message text, links, or attachments.

Signals, nothing fired, technical: Nothing in the headers points to forgery or spam. That is a statement about the headers only: the body, links and attachments are not examined.

Signature check, plain: Checked today, November 13, 2026. What the recipient's email provider recorded when the message arrived is shown separately.

Signature check, technical: Checked November 13, 2026 from the pasted text. Each key was looked up over DNS over HTTPS at cloudflare-dns.com, and each signature was verified in this browser (RFC 6376 3.7). The results mx.receiver.example recorded at delivery are a separate fact and are not changed by this check.

Signature check label, plain: Not checked

Signature check, on arrival, plain: The recipient's email provider recorded that this signature passed when the message arrived.

Signature check, on arrival, technical: mx.receiver.example recorded dkim=pass for d=shop.example s=s1 at delivery.

Signature check, today, plain: This signature uses an outdated method (rsa-sha1), so this page doesn't check it.

Signature check, today, technical: a=rsa-sha1 is not verified here. RFC 8301 3.1 says rsa-sha1 MUST NOT be used for signing or verifying.

## signature check: unknown method

Plain headline: This message passed the sender check (DMARC). It was signed by shop.example, the domain in the From address.

Technical headline: DMARC at mx.receiver.example passed because DKIM d=shop.example s=s1 passed, and it aligns with the From domain shop.example (RFC5322.From).

Cause, plain: A message passes when it's signed by, or sent for, the domain in its From address, and this one was.

Cause, technical: For shop.example, the pass comes from aligned DKIM, which still passes after a forward if nothing alters the signed headers or body.

Policy, plain: The message passed, so the sender's DMARC setting didn't come into play.

Policy, technical: shop.example publishes p=reject, which asks for failing mail to be refused. This message passed, so the policy did not come into play.

Delivery, plain: Mail sent this way meets the rules Gmail, Yahoo, and Microsoft's Outlook.com set for proving who sent a message. Those rules also cover spam complaints and unsubscribe links, which the headers don't show.

Delivery, technical: SPF and DKIM both pass, and one aligns with the From domain shop.example, which publishes a DMARC record. That meets the authentication requirements for bulk senders. Google's Email sender guidelines, Yahoo's Sender Best Practices, and Microsoft's Outlook.com requirements for high volume senders all say so. Their spam rate and unsubscribe requirements are outside the headers.

Detail 1, plain: The message was signed by shop.example, which belongs to the sender.

Detail 1, technical: DKIM passed for d=shop.example s=s1, which aligns with shop.example.

Detail 2, plain: The sending server is approved, but by bounce.mailer.example, not by the sender's own domain.

Detail 2, technical: SPF passed for bounce.mailer.example, which does not align with shop.example. A pass on another domain does not count for DMARC.

Fix 1, plain: Nothing needs fixing. If you want both checks to match, give the service that sends this mail a custom return address on shop.example (often called a custom return path).

Fix 1, technical: Alignment comes from DKIM alone, which is enough. For SPF to align too, set a custom Return-Path domain under shop.example at the sending service.

Limit 1, plain: This page assumes the usual, looser domain match. A domain's DMARC setting can demand an exact match, and the headers don't show that setting.

Limit 1, technical: Alignment is computed in relaxed mode, the DMARC default, with strict mode beside it. adkim and aspf are set in the DMARC record, which is not in the headers.

Sender signals, plain: Yes, as far as the headers show.

Sender signals, technical: No flag fired: DMARC passed for shop.example, and the display name, Reply-To, and From domain raise nothing.

Spam signals, plain: These headers can't say. They carry no spam rating from the receiving system that this page can read.

Spam signals, technical: No spam filter result that this page can read was written by the receiver.

Signals, nothing fired, plain: Nothing in the headers points to forgery or spam. That covers the headers only, because this page doesn't judge the message text, links, or attachments.

Signals, nothing fired, technical: Nothing in the headers points to forgery or spam. That is a statement about the headers only: the body, links and attachments are not examined.

Signature check, plain: Checked today, November 13, 2026. What the recipient's email provider recorded when the message arrived is shown separately.

Signature check, technical: Checked November 13, 2026 from the pasted text. Each key was looked up over DNS over HTTPS at cloudflare-dns.com, and each signature was verified in this browser (RFC 6376 3.7). The results mx.receiver.example recorded at delivery are a separate fact and are not changed by this check.

Signature check label, plain: Not checked

Signature check, on arrival, plain: The recipient's email provider recorded that this signature passed when the message arrived.

Signature check, on arrival, technical: mx.receiver.example recorded dkim=pass for d=shop.example s=s1 at delivery.

Signature check, today, plain: This signature uses a method this page doesn't know, so it wasn't checked.

Signature check, today, technical: a=rsa-sha512 is not rsa-sha256 or ed25519-sha256, so nothing was looked up or verified.

## signature check: signature incomplete

Plain headline: This message passed the sender check (DMARC). It was signed by shop.example, the domain in the From address.

Technical headline: DMARC at mx.receiver.example passed because DKIM d=shop.example s=s1 passed, and it aligns with the From domain shop.example (RFC5322.From).

Cause, plain: A message passes when it's signed by, or sent for, the domain in its From address, and this one was.

Cause, technical: For shop.example, the pass comes from aligned DKIM, which still passes after a forward if nothing alters the signed headers or body.

Policy, plain: The message passed, so the sender's DMARC setting didn't come into play.

Policy, technical: shop.example publishes p=reject, which asks for failing mail to be refused. This message passed, so the policy did not come into play.

Delivery, plain: Mail sent this way meets the rules Gmail, Yahoo, and Microsoft's Outlook.com set for proving who sent a message. Those rules also cover spam complaints and unsubscribe links, which the headers don't show.

Delivery, technical: SPF and DKIM both pass, and one aligns with the From domain shop.example, which publishes a DMARC record. That meets the authentication requirements for bulk senders. Google's Email sender guidelines, Yahoo's Sender Best Practices, and Microsoft's Outlook.com requirements for high volume senders all say so. Their spam rate and unsubscribe requirements are outside the headers.

Detail 1, plain: The message was signed by shop.example, which belongs to the sender.

Detail 1, technical: DKIM passed for d=shop.example s=s1, which aligns with shop.example.

Detail 2, plain: The sending server is approved, but by bounce.mailer.example, not by the sender's own domain.

Detail 2, technical: SPF passed for bounce.mailer.example, which does not align with shop.example. A pass on another domain does not count for DMARC.

Fix 1, plain: Nothing needs fixing. If you want both checks to match, give the service that sends this mail a custom return address on shop.example (often called a custom return path).

Fix 1, technical: Alignment comes from DKIM alone, which is enough. For SPF to align too, set a custom Return-Path domain under shop.example at the sending service.

Limit 1, plain: This page assumes the usual, looser domain match. A domain's DMARC setting can demand an exact match, and the headers don't show that setting.

Limit 1, technical: Alignment is computed in relaxed mode, the DMARC default, with strict mode beside it. adkim and aspf are set in the DMARC record, which is not in the headers.

Sender signals, plain: Yes, as far as the headers show.

Sender signals, technical: No flag fired: DMARC passed for shop.example, and the display name, Reply-To, and From domain raise nothing.

Spam signals, plain: These headers can't say. They carry no spam rating from the receiving system that this page can read.

Spam signals, technical: No spam filter result that this page can read was written by the receiver.

Signals, nothing fired, plain: Nothing in the headers points to forgery or spam. That covers the headers only, because this page doesn't judge the message text, links, or attachments.

Signals, nothing fired, technical: Nothing in the headers points to forgery or spam. That is a statement about the headers only: the body, links and attachments are not examined.

Signature check, plain: Checked today, November 13, 2026. What the recipient's email provider recorded when the message arrived is shown separately.

Signature check, technical: Checked November 13, 2026 from the pasted text. Each key was looked up over DNS over HTTPS at cloudflare-dns.com, and each signature was verified in this browser (RFC 6376 3.7). The results mx.receiver.example recorded at delivery are a separate fact and are not changed by this check.

Signature check label, plain: Not checked

Signature check, on arrival, plain: The recipient's email provider recorded that this signature passed when the message arrived.

Signature check, on arrival, technical: mx.receiver.example recorded dkim=pass for d=shop.example s=s1 at delivery.

Signature check, today, plain: The signature in these headers is missing parts, so it couldn't be checked. Copy the full headers again.

Signature check, today, technical: The DKIM-Signature field lacks a usable d=, s=, h=, bh= or b=, so nothing was looked up or verified.

## signature check: browser without Ed25519

Plain headline: This message passed the sender check (DMARC). It was signed by shop.example, the domain in the From address.

Technical headline: DMARC at mx.receiver.example passed because DKIM d=shop.example s=s1 passed, and it aligns with the From domain shop.example (RFC5322.From).

Cause, plain: A message passes when it's signed by, or sent for, the domain in its From address, and this one was.

Cause, technical: For shop.example, the pass comes from aligned DKIM, which still passes after a forward if nothing alters the signed headers or body.

Policy, plain: The message passed, so the sender's DMARC setting didn't come into play.

Policy, technical: shop.example publishes p=reject, which asks for failing mail to be refused. This message passed, so the policy did not come into play.

Delivery, plain: Mail sent this way meets the rules Gmail, Yahoo, and Microsoft's Outlook.com set for proving who sent a message. Those rules also cover spam complaints and unsubscribe links, which the headers don't show.

Delivery, technical: SPF and DKIM both pass, and one aligns with the From domain shop.example, which publishes a DMARC record. That meets the authentication requirements for bulk senders. Google's Email sender guidelines, Yahoo's Sender Best Practices, and Microsoft's Outlook.com requirements for high volume senders all say so. Their spam rate and unsubscribe requirements are outside the headers.

Detail 1, plain: The message was signed by shop.example, which belongs to the sender.

Detail 1, technical: DKIM passed for d=shop.example s=s1, which aligns with shop.example.

Detail 2, plain: The sending server is approved, but by bounce.mailer.example, not by the sender's own domain.

Detail 2, technical: SPF passed for bounce.mailer.example, which does not align with shop.example. A pass on another domain does not count for DMARC.

Fix 1, plain: Nothing needs fixing. If you want both checks to match, give the service that sends this mail a custom return address on shop.example (often called a custom return path).

Fix 1, technical: Alignment comes from DKIM alone, which is enough. For SPF to align too, set a custom Return-Path domain under shop.example at the sending service.

Limit 1, plain: This page assumes the usual, looser domain match. A domain's DMARC setting can demand an exact match, and the headers don't show that setting.

Limit 1, technical: Alignment is computed in relaxed mode, the DMARC default, with strict mode beside it. adkim and aspf are set in the DMARC record, which is not in the headers.

Sender signals, plain: Yes, as far as the headers show.

Sender signals, technical: No flag fired: DMARC passed for shop.example, and the display name, Reply-To, and From domain raise nothing.

Spam signals, plain: These headers can't say. They carry no spam rating from the receiving system that this page can read.

Spam signals, technical: No spam filter result that this page can read was written by the receiver.

Signals, nothing fired, plain: Nothing in the headers points to forgery or spam. That covers the headers only, because this page doesn't judge the message text, links, or attachments.

Signals, nothing fired, technical: Nothing in the headers points to forgery or spam. That is a statement about the headers only: the body, links and attachments are not examined.

Signature check, plain: Checked today, November 13, 2026. What the recipient's email provider recorded when the message arrived is shown separately.

Signature check, technical: Checked November 13, 2026 from the pasted text. Each key was looked up over DNS over HTTPS at cloudflare-dns.com, and each signature was verified in this browser (RFC 6376 3.7). The results mx.receiver.example recorded at delivery are a separate fact and are not changed by this check.

Signature check label, plain: Not checked

Signature check, on arrival, plain: The recipient's email provider recorded that this signature passed when the message arrived.

Signature check, on arrival, technical: mx.receiver.example recorded dkim=pass for d=shop.example s=s1 at delivery.

Signature check, today, plain: This browser can't check this kind of signature. Try the current version of Chrome, Firefox, or Safari.

Signature check, today, technical: This browser's WebCrypto has no Ed25519, so the ed25519-sha256 signature (RFC 8463) was not verified. The key at s1._domainkey.shop.example was found.

## Delivery sources

RFC 9989, DMARC, section 4.7: what p=quarantine and p=reject ask of a receiver. Section 1 says a receiver is not required to honor the request. https://www.rfc-editor.org/rfc/rfc9989

RFC 7960, sections 2.2 and 3.2.3: forwarding breaks SPF, and a mailing list that modifies a message breaks its DKIM signature. https://www.rfc-editor.org/rfc/rfc7960

RFC 8301, section 3.1: rsa-sha1 signatures are not accepted. https://www.rfc-editor.org/rfc/rfc8301

Google, Email sender guidelines: all senders need SPF or DKIM. Senders of 5,000 or more messages a day to Gmail accounts need SPF and DKIM, a DMARC record (p=none is enough), and a From domain aligned with the SPF or DKIM domain. Mail that falls short might be marked as spam or rejected with a 5.7.26 error. https://support.google.com/a/answer/81126

Yahoo, Sender Best Practices: all senders need SPF or DKIM. Bulk senders need both, a DMARC record of at least p=none that passes, and an aligned From domain. Yahoo gives no number for bulk. https://senders.yahooinc.com/best-practices/

Microsoft, Outlook's New Requirements for High Volume Senders (April 2025): domains sending more than 5,000 messages a day to outlook.com, hotmail.com, and live.com need SPF and DKIM to pass and a DMARC record of at least p=none aligned with one of them. The post says both junk and rejection (550 5.7.515), so the lines say either. https://techcommunity.microsoft.com/blog/microsoftdefenderforoffice365blog/strengthening-email-ecosystem-outlook%E2%80%99s-new-requirements-for-high%E2%80%90volume-senders/4399730

## Signal questions

sender: Is the sender who it appears to be?

spam: Did the receiving system treat it as spam?

## Signature check labels

failed: Find out why the signature failed

check: Check the signature

again: Check again

under: This looks up the sender's published key (DKIM key) and checks the signature again.

busy: Checking the signature.

sample: This check runs on your own messages, not on the samples.

arrived: When the message arrived

today: Checked today

who: Who fixes it

## Filter code meanings

Microsoft card note. Technical: Fields of X-Forefront-Antispam-Report that Microsoft does not document are left out; Microsoft says they are for its own diagnostics. In cloud organizations CAT, not SCL, says how the message was filtered. The tenant's threshold decides the BCL action (7 by default, 6 Standard, 5 Strict); it is not in the headers. Plain: Only the parts Microsoft explains publicly are shown. Microsoft's threat category (CAT), not its spam score (SCL), decides where the message went. Each organization sets its own limit for bulk mail, and the headers don't show it.

Microsoft CAT NONE (pass). Technical: Threat category: No threat policy applied. Plain: No threat was detected.

Microsoft CAT SPM (fail). Technical: Threat category: Spam. Plain: Filed as spam.

Microsoft CAT HSPM (fail). Technical: Threat category: High confidence spam. Plain: Filed as spam with high confidence.

Microsoft CAT PHSH (fail). Technical: Threat category: Phishing. Plain: Treated as phishing.

Microsoft CAT HPHSH (fail). Technical: Threat category: High confidence phishing. Plain: Treated as phishing with high confidence.

Microsoft CAT HPHISH (fail). Technical: Threat category: High confidence phishing. Plain: Treated as phishing with high confidence.

Microsoft CAT BULK (warn). Technical: Threat category: Bulk. Plain: Treated as bulk mail, such as a newsletter.

Microsoft CAT SPOOF (fail). Technical: Threat category: Spoofing. Plain: Treated as a forged sender.

Microsoft CAT MALW (fail). Technical: Threat category: Malware. Plain: Malware was found.

Microsoft CAT AMP (fail). Technical: Threat category: Anti-malware policy. Plain: Caught by the malware filter.

Microsoft CAT FTBP (fail). Technical: Threat category: Anti-malware common attachments filter. Plain: Caught by the attachment type filter.

Microsoft CAT SAP (fail). Technical: Threat category: Safe Attachments (Defender for Office 365). Plain: Caught by attachment scanning.

Microsoft CAT DIMP (fail). Technical: Threat category: Domain impersonation (Defender for Office 365). Plain: Looked like it was pretending to be a protected domain.

Microsoft CAT UIMP (fail). Technical: Threat category: User impersonation (Defender for Office 365). Plain: Looked like it was pretending to be a protected person.

Microsoft CAT GIMP (fail). Technical: Threat category: Mailbox intelligence impersonation (Defender for Office 365). Plain: Looked like it was pretending to be someone the recipient usually hears from.

Microsoft CAT BIMP (fail). Technical: Threat category: Brand impersonation (Defender for Office 365). Plain: Looked like it was pretending to be a known brand.

Microsoft CAT INTOS (fail). Technical: Threat category: Intra-organization phishing. Plain: Treated as phishing from inside the organization.

Microsoft CAT OSPM (warn). Technical: Threat category: Outbound spam. Plain: Treated as outgoing spam.

Microsoft SFV NSPM (pass). Technical: Spam filtering marked it as not spam. Plain: Microsoft's spam filter decided this isn't spam.

Microsoft SFV SPM (fail). Technical: Spam filtering marked it as spam. Plain: Microsoft's spam filter decided this is spam.

Microsoft SFV BLK (fail). Technical: Filtering skipped; blocked because the sender is on the user's Blocked Senders list. Plain: The recipient had blocked this sender.

Microsoft SFV SFE (pass). Technical: Filtering skipped; allowed because the sender is on the user's Safe Senders list. Plain: The recipient had marked this sender as safe, so filtering was skipped.

Microsoft SFV SKA (pass). Technical: Filtering skipped: the sender is on an allowed senders or domains list in an anti-spam policy. Plain: An administrator had allowed this sender, so filtering was skipped.

Microsoft SFV SKB (fail). Technical: Marked as spam: the sender matched a blocked senders or domains list in an anti-spam policy. Plain: An administrator had blocked this sender.

Microsoft SFV SKI (pass). Technical: Filtering skipped: the source IP is on the IP Allow List in the connection filter policy. Plain: An administrator had allowed the sending server, so filtering was skipped.

Microsoft SFV SKN (pass). Technical: Filtering bypassed by an Exchange mail flow rule. Plain: A rule set by an administrator let this message skip the spam filter.

Microsoft SFV SKQ (info). Technical: Released from quarantine to the recipients. Plain: The message was held in quarantine and then released.

Microsoft SFV SKS (fail). Technical: Marked as spam before filtering, by a mail flow rule or an on-premises hybrid decision. Plain: A rule set by an administrator marked this message as spam.

Microsoft SCL -1 (pass). Technical: Spam confidence level -1: filtering skipped. Plain: Spam filtering was skipped.

Microsoft SCL 0 (pass). Technical: Spam confidence level 0: not spam. Plain: Not spam.

Microsoft SCL 1 (pass). Technical: Spam confidence level 1: not spam. Plain: Not spam.

Microsoft SCL 2 (info). Technical: Spam confidence level 2 is inside Microsoft's range but has no published meaning, so it is shown as written. Plain: Microsoft recorded a spam score this page can't interpret.

Microsoft SCL 5 (fail). Technical: Spam confidence level 5: spam. Plain: Rated as spam.

Microsoft SCL 6 (fail). Technical: Spam confidence level 6: spam. Plain: Rated as spam.

Microsoft SCL 7 (warn). Technical: Spam confidence level 7. Microsoft gives this value no meaning of its own and says 5 or higher generally means the message is considered bad. Plain: Rated as likely spam.

Microsoft SCL 9 (fail). Technical: Spam confidence level 9: high confidence spam. Plain: Rated as spam with high confidence.

Microsoft SCL 10 (info). Technical: SCL 10 is not in Microsoft's published table, so it is shown as written. Plain: Microsoft recorded a code this page doesn't know. It's shown as written.

Microsoft BCL 0 (pass). Technical: Bulk complaint level 0: not from a bulk sender. Plain: Not bulk mail.

Microsoft BCL 1 (info). Technical: Bulk complaint level 1: a bulk sender that generates few complaints. Plain: Bulk mail from a sender with few complaints.

Microsoft BCL 2 (info). Technical: Bulk complaint level 2: a bulk sender that generates few complaints. Plain: Bulk mail from a sender with few complaints.

Microsoft BCL 3 (info). Technical: Bulk complaint level 3: a bulk sender that generates few complaints. Plain: Bulk mail from a sender with few complaints.

Microsoft BCL 4 (warn). Technical: Bulk complaint level 4: a bulk sender that generates a mixed number of complaints. Plain: Bulk mail from a sender people sometimes complain about.

Microsoft BCL 5 (warn). Technical: Bulk complaint level 5: a bulk sender that generates a mixed number of complaints. Plain: Bulk mail from a sender people sometimes complain about.

Microsoft BCL 6 (warn). Technical: Bulk complaint level 6: a bulk sender that generates a mixed number of complaints. Plain: Bulk mail from a sender people sometimes complain about.

Microsoft BCL 7 (warn). Technical: Bulk complaint level 7: a bulk sender that generates a mixed number of complaints. Plain: Bulk mail from a sender people sometimes complain about.

Microsoft BCL 8 (fail). Technical: Bulk complaint level 8: a bulk sender that generates a high number of complaints. Plain: Bulk mail from a sender people often complain about.

Microsoft BCL 9 (fail). Technical: Bulk complaint level 9: a bulk sender that generates a high number of complaints. Plain: Bulk mail from a sender people often complain about.

Microsoft PCL 1 (pass). Technical: Phishing confidence level 1: Neutral, the content is not likely phishing. Plain: The content didn't look like phishing.

Microsoft PCL 4 (warn). Technical: Phishing confidence level 4: Suspicious, the content is likely phishing. Plain: The content looked like phishing.

Microsoft PCL 9 (info). Technical: PCL 9 is not in Microsoft's published table, so it is shown as written. Plain: Microsoft recorded a code this page doesn't know. It's shown as written.

Microsoft IPV CAL (pass). Technical: Skipped spam filtering: the source IP is on the IP Allow List. Plain: An administrator had allowed the sending server.

Microsoft IPV NLI (pass). Technical: The IP address was not found on any IP reputation list. Plain: The sending server wasn't on any reputation list Microsoft checks.

Microsoft IPV XYZ (info). Technical: IPV XYZ is not in Microsoft's published table, so it is shown as written. Plain: Microsoft recorded a code this page doesn't know. It's shown as written.

Microsoft SRV BULK (warn). Technical: Identified as bulk by spam filtering and the BCL threshold. Plain: Treated as bulk mail.

Microsoft SFTY 9.19 (warn). Technical: Identified as phishing and given the domain impersonation safety tip. Plain: Outlook showed a warning: domain impersonation.

Microsoft SFTY 9.20 (warn). Technical: Identified as phishing and given the user impersonation safety tip. Plain: Outlook showed a warning: user impersonation.

Microsoft SFTY 9.25 (warn). Technical: Identified as phishing and given the first contact safety tip. Plain: Outlook showed a warning: first contact.

Microsoft DIR INB (info). Technical: Direction: inbound message. Plain: Microsoft treated this as inbound mail.

Microsoft DIR OUT (info). Technical: Direction: outbound message. Plain: Microsoft treated this as outbound mail.

Microsoft DIR INT (info). Technical: Direction: internal message. Plain: Microsoft treated this as internal mail.

Microsoft CIP 198.51.100.44 (info). Technical: Connecting IP as Microsoft saw it. Plain: The address of the server that handed the message to Microsoft.

Microsoft CTRY US (info). Technical: Country or region of the connecting IP, which may differ from where the message started. Plain: Where the server that handed it over is.

Microsoft H o1.sender.example (info). Technical: HELO or EHLO name the connecting server gave. Plain: The name the sending server gave itself.

Microsoft PTR o1.sender.example (info). Technical: Reverse DNS of the connecting IP, as Microsoft looked it up. Plain: The name registered for the sending server's address.

Microsoft SFS (13230040) (info). Technical: SFS (13230040) is not in Microsoft's published table, so it is shown as written. Plain: Microsoft recorded a code this page doesn't know. It's shown as written.

Microsoft AuthAs Internal (info). Technical: Treated as internal, authenticated mail. Plain: Microsoft treated this as mail from inside the organization.

Microsoft AuthAs Anonymous (info). Technical: Treated as external, unauthenticated mail. Plain: Microsoft treated this as mail from outside the organization.

Microsoft AuthAs External (info). Technical: Authentication source External. Plain: Microsoft recorded this as authenticated mail from outside the organization.

Microsoft AuthAs Partner (info). Technical: Authentication source Partner. Plain: Microsoft recorded this as mail from a partner organization.

Microsoft AuthSource BN3PEPF0000B077.namprd04.prod.outlook.com (info). Technical: The server that evaluated authentication for the organization. Plain: The Microsoft server that checked who sent this.

Microsoft compauth pass reason=100 (pass). Technical: SPF or DKIM passed and aligns with the From domain. Plain: Microsoft's own sender check passed.

Microsoft compauth pass reason=101 (pass). Technical: DKIM signed by the From domain. Plain: Microsoft's own sender check passed.

Microsoft compauth pass reason=102 (pass). Technical: SPF passed and the MAIL FROM aligns with the From domain. Plain: Microsoft's own sender check passed.

Microsoft compauth pass reason=103 (pass). Technical: The From domain aligns with the PTR record of the source IP. Plain: Microsoft's own sender check passed.

Microsoft compauth pass reason=104 (pass). Technical: The PTR record of the source IP aligns with the From domain. Plain: Microsoft's own sender check passed.

Microsoft compauth pass reason=108 (pass). Technical: An earlier legitimate hop modified the body, so the DKIM signature did not verify. Plain: Microsoft's own sender check passed.

Microsoft compauth pass reason=109 (pass). Technical: No DMARC record, but the message would pass. Plain: Microsoft's own sender check passed.

Microsoft compauth pass reason=111 (pass). Technical: DMARC hit an error, but SPF or DKIM aligns with the From domain. Plain: Microsoft's own sender check passed.

Microsoft compauth pass reason=112 (pass). Technical: A DNS timeout prevented the DMARC record lookup. Plain: Microsoft's own sender check passed.

Microsoft compauth pass reason=115 (pass). Technical: Sent from a Microsoft 365 organization where the From domain is an accepted domain. Plain: Microsoft's own sender check passed.

Microsoft compauth pass reason=116 (pass). Technical: The MX record of the From domain aligns with the PTR record of the connecting IP. Plain: Microsoft's own sender check passed.

Microsoft compauth pass reason=130 (pass). Technical: An ARC result from a trusted ARC sealer overrode the DMARC result. Plain: Microsoft's own sender check passed.

Microsoft compauth softpass reason=201 (warn). Technical: The PTR of the From domain aligns with the subnet of the connecting IP's PTR. Plain: Microsoft's own sender check gave a soft pass.

Microsoft compauth softpass reason=202 (warn). Technical: The From domain aligns with the domain of the connecting IP's PTR record. Plain: Microsoft's own sender check gave a soft pass.

Microsoft compauth pass reason=501 (pass). Technical: DMARC not enforced: a valid bounce where sender and recipient had prior contact. Plain: Microsoft's own sender check passed.

Microsoft compauth pass reason=502 (pass). Technical: DMARC not enforced: a valid bounce for a message this organization sent. Plain: Microsoft's own sender check passed.

Microsoft compauth fail reason=601 (fail). Technical: The From domain is one of the organization's accepted domains (self-to-self or intra-org spoofing). Plain: Microsoft's own sender check failed.

Microsoft compauth none reason=905 (info). Technical: DMARC not enforced because of complex routing, such as mail through on-premises Exchange or another service first. Plain: Microsoft's own sender check was bypassed.

Microsoft compauth fail reason=000 (fail). Technical: Explicit authentication failed: DMARC failed and the policy is quarantine or reject. Plain: Microsoft's own sender check failed.

Microsoft compauth fail reason=001 (fail). Technical: Implicit authentication failed: no authentication records, or only weak ones (SPF ~all or ?all, DMARC p=none). Plain: Microsoft's own sender check failed.

Microsoft compauth fail reason=002 (fail). Technical: The organization prohibits this sender and domain pair from sending spoofed mail. Plain: Microsoft's own sender check failed.

Microsoft compauth fail reason=010 (fail). Technical: DMARC failed with quarantine or reject, and the From domain is one of the organization's own accepted domains. Plain: Microsoft's own sender check failed.

Microsoft compauth pass reason=701 (pass). Technical: DMARC not enforced because the organization has a history of legitimate mail from this infrastructure. Plain: Microsoft's own sender check passed.

Microsoft compauth pass reason=702 (pass). Technical: DMARC not enforced because the organization has a history of legitimate mail from this infrastructure. Plain: Microsoft's own sender check passed.

Microsoft compauth pass reason=703 (pass). Technical: DMARC not enforced because the organization has a history of legitimate mail from this infrastructure. Plain: Microsoft's own sender check passed.

Microsoft compauth pass reason=704 (pass). Technical: DMARC not enforced because the organization has a history of legitimate mail from this infrastructure. Plain: Microsoft's own sender check passed.

Microsoft compauth softpass reason=299 (warn). Technical: Soft-passed implicit authentication (code 299 has no entry of its own). Plain: Microsoft's own sender check gave a soft pass.

Microsoft compauth none reason=399 (info). Technical: Not checked for composite authentication (code 399 has no entry of its own). Plain: Microsoft's own sender check was skipped.

Microsoft compauth none reason=499 (info). Technical: Bypassed composite authentication (code 499 has no entry of its own). Plain: Microsoft's own sender check was bypassed.

Microsoft compauth fail reason=699 (fail). Technical: Failed implicit authentication (code 699 has no entry of its own). Plain: Microsoft's own sender check failed.

Microsoft compauth pass reason=799 (pass). Technical: Passed implicit authentication (code 799 has no entry of its own). Plain: Microsoft's own sender check passed.

Microsoft compauth none reason=999 (info). Technical: Bypassed composite authentication (code 999 has no entry of its own). Plain: Microsoft's own sender check was bypassed.

Microsoft compauth fail reason=801 (fail). Technical: Reason code 801 is not in Microsoft's published table, so it is shown as written. Plain: Microsoft's own sender check failed. Its reason code isn't one Microsoft explains publicly.

Proofpoint rule notspam (pass). Technical: Classification rule notspam: not spam. Plain: Proofpoint decided this isn't spam.

Proofpoint policy default (info). Technical: Policy route applied. Plain: The Proofpoint rule set that handled the message.

Proofpoint score 0 (info). Technical: score 0. The customer sets the thresholds, which are not in the headers, so the score is shown as written. Plain: A Proofpoint score of 0. What it leads to is set by the receiving organization.

Proofpoint spamscore 0 (info). Technical: spamscore 0. The customer sets the thresholds, which are not in the headers, so the score is shown as written. Plain: A Proofpoint score of 0. What it leads to is set by the receiving organization.

Proofpoint phishscore 0 (info). Technical: phishscore 0. The customer sets the thresholds, which are not in the headers, so the score is shown as written. Plain: A Proofpoint score of 0. What it leads to is set by the receiving organization.

Proofpoint bulkscore 0 (info). Technical: bulkscore 0. The customer sets the thresholds, which are not in the headers, so the score is shown as written. Plain: A Proofpoint score of 0. What it leads to is set by the receiving organization.

Proofpoint malwarescore 0 (info). Technical: malwarescore 0. The customer sets the thresholds, which are not in the headers, so the score is shown as written. Plain: A Proofpoint score of 0. What it leads to is set by the receiving organization.

Proofpoint suspectscore 0 (info). Technical: suspectscore 0. The customer sets the thresholds, which are not in the headers, so the score is shown as written. Plain: A Proofpoint score of 0. What it leads to is set by the receiving organization.

Proofpoint impostorscore 0 (info). Technical: impostorscore 0. The customer sets the thresholds, which are not in the headers, so the score is shown as written. Plain: A Proofpoint score of 0. What it leads to is set by the receiving organization.

Proofpoint adultscore 0 (info). Technical: adultscore 0. The customer sets the thresholds, which are not in the headers, so the score is shown as written. Plain: A Proofpoint score of 0. What it leads to is set by the receiving organization.

Proofpoint mlxscore 0 (info). Technical: mlxscore 0. The customer sets the thresholds, which are not in the headers, so the score is shown as written. Plain: A Proofpoint score of 0. What it leads to is set by the receiving organization.

Proofpoint clxscore 0 (info). Technical: clxscore 0. The customer sets the thresholds, which are not in the headers, so the score is shown as written. Plain: A Proofpoint score of 0. What it leads to is set by the receiving organization.

Proofpoint rule spam (fail). Technical: Classification rule spam: spam. Plain: Proofpoint decided this is spam.

Proofpoint rule custom_rule (info). Technical: Classification rule custom_rule. The customer names its own rules, so it is shown as written. Plain: Proofpoint applied a rule named custom_rule.

Mimecast Spam-Score 4 (info). Technical: Mimecast spam score; higher is worse. Mimecast publishes no scale for it and the customer sets the thresholds. Plain: Mimecast's spam score. Higher is worse.

Mimecast Impersonation-Protect Similar Monitored External Domain (warn). Technical: Impersonation Protect (policy Default) flagged: Similar Monitored External Domain. Plain: Mimecast thought the sender might be pretending to be someone.

Mimecast Bulk-Signature yes (info). Technical: Mimecast bulk signature, shown as written. Plain: Mimecast checked whether this is bulk mail.

Mimecast Impersonation-Protect nothing fired (pass). Technical: Impersonation Protect (policy Default): none of its 1 checks fired. Plain: Mimecast found no sign the sender was pretending to be someone.

Mimecast Impersonation-Protect opaque (info). Technical: Impersonation Protect ran; its value is in a form this page does not read, so it is shown as written. Plain: Mimecast checked whether the sender was pretending to be someone.

Mimecast X-Mimecast-Spam-Signature present (info). Technical: Mimecast handled this message; its other fields carry no documented result. Plain: Mimecast handled this message.

Cisco Anti-Spam-Filtered true (info). Technical: Anti-spam scanning ran on this message. Plain: Cisco scanned this message for spam.

Cisco X-IronPort-Anti-Spam-Result opaque (info). Technical: An encoded anti-spam result. Cisco does not publish how to read it. Plain: Cisco recorded a result in a form only Cisco can read.

Cisco X-IPAS-Result opaque (info). Technical: An encoded anti-spam result. Cisco does not publish how to read it. Plain: Cisco recorded a result in a form only Cisco can read.

Cisco Reputation -3.1 (info). Technical: SenderBase reputation score of the connecting IP, from -10 to +10; lower is worse. The customer's mail policies decide what a score does. Plain: Cisco's reputation score for the sending server. Lower is worse.

Cisco AV E=Sophos;i="6.00" (info). Technical: Anti-virus engine stamp, shown as written. Plain: Cisco scanned this message for viruses.

Cisco X-IronPort-MID 12345 (info). Technical: A Cisco Secure Email field with no documented result, shown as written. Plain: Cisco handled this message.

Barracuda Spam-Status Yes (fail). Technical: Classified as spam: score 7.1, tag level 3.5, block level 6.0. Plain: Barracuda decided this is spam.

Barracuda Spam-Status No (pass). Technical: Classified as not spam: score 0.2, tag level 3.5, block level 6.0. Plain: Barracuda decided this isn't spam.

Barracuda Spam-Status Maybe (info). Technical: Spam-Status Maybe is not in Barracuda's published table, so it is shown as written. Plain: Barracuda recorded a code this page doesn't know. It's shown as written.

Barracuda Spam-Score 1.5 (info). Technical: Barracuda score; the customer sets the thresholds. Plain: Barracuda's spam score.

Barracuda Spam-Flag YES (fail). Technical: Flagged as spam. Plain: Barracuda flagged this as spam.

Barracuda Spam-Flag NO (pass). Technical: Not flagged as spam. Plain: Barracuda didn't flag this as spam.

SpamAssassin X-Spam-Status Yes (fail). Technical: Classified as spam: score 6.2 against a threshold of 5.0. Plain: The filter decided this is spam.

SpamAssassin tests BAYES_99,URIBL_BLOCKED (info). Technical: Rules that matched. Plain: The filter rules this message matched.

SpamAssassin X-Spam-Status No (pass). Technical: Classified as not spam: score 0.1 against a threshold of 5.0. Plain: The filter decided this isn't spam.

SpamAssassin X-Spam-Status Unclear (info). Technical: X-Spam-Status Unclear is not in SpamAssassin's published table, so it is shown as written. Plain: SpamAssassin recorded a code this page doesn't know. It's shown as written.

SpamAssassin X-Spam-Flag YES (fail). Technical: Flagged as spam. Plain: The filter flagged this as spam.

SpamAssassin X-Spam-Score 6.2 (info). Technical: Spam score; the threshold is not in the headers. Plain: The filter's spam score.

SpamAssassin X-Spam-Flag NO (pass). Technical: Not flagged as spam. Plain: The filter didn't flag this as spam.

Rspamd X-Rspamd-Action no action (pass). Technical: No action: the message is not spam. Plain: Rspamd decided this isn't spam.

Rspamd X-Rspamd-Action greylist (warn). Technical: Greylisted: delivery was delayed once. Plain: Rspamd delayed the message once as a test.

Rspamd X-Rspamd-Action add header (fail). Technical: Marked as spam with a header. Plain: Rspamd marked this as spam.

Rspamd X-Rspamd-Action rewrite subject (fail). Technical: Marked as spam in the subject line. Plain: Rspamd marked this as spam in its subject.

Rspamd X-Rspamd-Action soft reject (warn). Technical: Temporarily refused. Plain: Rspamd asked the sender to try again later.

Rspamd X-Rspamd-Action reject (fail). Technical: Rejected as spam. Plain: Rspamd refused this as spam.

Rspamd X-Rspamd-Action quarantine (info). Technical: X-Rspamd-Action quarantine is not in Rspamd's published table, so it is shown as written. Plain: Rspamd recorded a code this page doesn't know. It's shown as written.

Rspamd X-Spamd-Result 16.20 / 15.00 (fail). Technical: Score 16.20 against a reject threshold of 15.00: over it. Plain: Rspamd scored this as spam.

Rspamd X-Spamd-Result 2.10 / 15.00 (info). Technical: Score 2.10 against a reject threshold of 15.00: under it. Lower actions, such as adding a spam header, have their own thresholds, which are not in the headers. Plain: Rspamd scored this below its refusal level.

Rspamd X-Spamd-Result unreadable (info). Technical: X-Spamd-Result unreadable is not in Rspamd's published table, so it is shown as written. Plain: Rspamd recorded a code this page doesn't know. It's shown as written.
