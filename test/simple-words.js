'use strict';
// Words Simple never uses (CLAUDE.md, Copy), and tag=value forms like d=.
// A word inside a domain or a dotted name does not count.
exports.SIMPLE_BANNED = /(?<![\w.-])(aligned|alignment|unaligned|bounce|bounces|Return-Path|envelope|HELO|EHLO|selector|authserv|ARC|seal|seals|sealer|compauth|SCL|BCL|PCL|organizational domain|relay|relays|hop|hops|TLS|RFC|policy|policies)(?![\w.-])|\b[a-z]=/i;
