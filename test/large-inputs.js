// Synthetic large pastes for the speed test (and for timing the page by hand).
// Each builder returns a header block in the shape a real paste would take.
'use strict';

const TOP = [
  'From: Alex Rivera <alex@sender.example>',
  'To: Neil <neil@example.org>',
  'Subject: Large paste',
  'Date: Fri, 23 Oct 2026 16:10:48 +0000',
  'Message-ID: <large-1@sender.example>',
  'Return-Path: <alex@sender.example>',
  'Authentication-Results: mx.example.org; spf=pass smtp.mailfrom=sender.example; dkim=pass header.d=sender.example header.s=s1; dmarc=pass header.from=sender.example',
];

function received(i) {
  return 'Received: from relay' + i + '.relay.example (relay' + i + '.relay.example [198.51.100.' + (i % 250) + '])\r\n' +
    '        by relay' + (i + 1) + '.relay.example (Postfix) with ESMTPS id ' + i.toString(36).toUpperCase() + '\r\n' +
    '        (using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits))\r\n' +
    '        for <neil@example.org>; Fri, 23 Oct 2026 16:' + String(10 + (i % 40)).padStart(2, '0') + ':00 +0000 (UTC)';
}

// 2 MB with 400 Received fields: each Received is padded with a long X- field after it.
function twoMegabytes() {
  const lines = [];
  for (let i = 0; i < 400; i++) {
    lines.push(received(i));
    lines.push('X-Relay-Trace-' + i + ': ' + ('trace=' + i + ' hop ok; ').repeat(290));
  }
  return lines.concat(TOP).join('\r\n') + '\r\n';
}

// One header value of 500 KB on a single line with no spaces.
function longValue() {
  return [received(1), 'X-Blob: ' + 'aZ09+/'.repeat(500 * 1024 / 6)].concat(TOP).join('\n') + '\n';
}

// A DKIM-Signature whose b= value is 100 KB, folded the way signers fold it.
function bigDkim() {
  const b = 'abcdEFGH0123+/=='.repeat(100 * 1024 / 16).match(/.{1,76}/g).join('\r\n\t');
  return [received(1), 'DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed; d=sender.example; s=s1;\r\n\th=from:to:subject:date; bh=47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=;\r\n\tb=' + b].concat(TOP).join('\r\n') + '\r\n';
}

// Rich text from Outlook arrives as plain text with every space a no break space
// and soft hyphens through the words.
function outlookRich() {
  const lines = [];
  for (let i = 0; i < 60; i++) lines.push(received(i));
  const plain = lines.concat(TOP).join('\r\n') + '\r\n';
  return plain.replace(/ /g, ' ').replace(/([a-z]{3})(?=[a-z])/g, '$1­');
}

// 5000 fields.
function fiveThousandFields() {
  const lines = [];
  for (let i = 0; i < 4990; i++) lines.push('X-Field-' + i + ': value ' + i);
  return lines.concat(TOP).join('\n') + '\n';
}

module.exports = {
  '2 MB, 400 Received': twoMegabytes,
  '500 KB value, no spaces': longValue,
  'DKIM b= 100 KB': bigDkim,
  'Outlook rich text': outlookRich,
  '5000 fields': fiveThousandFields,
};

// Long unbroken runs in the fields whose regular expressions once went
// quadratic. 100 KB each; before the fix each took seconds.
const run = (name, unit) => () => [received(1), name + ': ' + unit.repeat(100 * 1024 / unit.length)].concat(TOP).join('\n') + '\n';
module.exports.RUNS = {
  'Received-SPF, 100 KB of a-': run('Received-SPF', 'a-'),
  'X-Proofpoint-Spam-Details, 100 KB of a': run('X-Proofpoint-Spam-Details', 'a'),
  'List-Id, 100 KB of a<': run('List-Id', 'a<'),
};
