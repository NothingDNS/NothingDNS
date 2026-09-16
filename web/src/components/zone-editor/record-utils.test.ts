import { describe, it, expect } from 'vitest';

import {
	buildRecordData,
	fieldsFromRecordData,
	quoteDNSString,
	stripOuterQuotes,
} from './record-utils';

// A literal backslash, composed at runtime so the assertions in this file
// never depend on test-source escape sequences.
const BS = String.fromCharCode(92);

describe('stripOuterQuotes / quoteDNSString round-trip', () => {
	it('decodes a backslash immediately before an escaped quote in one pass', () => {
		// A TXT value of backslash + quote. quoteDNSString escapes it as
		// BS BS " (the backslash doubled, then the quote escaped); the old
		// two-pass decoder consumed the backslash into the quote escape and
		// returned just a bare quote, silently changing the value.
		const original = BS + '"';
		const stored = quoteDNSString(original);
		expect(stripOuterQuotes(stored)).toBe(original);
	});

	it.each([
		['plain text', 'hello world'],
		['empty', ''],
		['lone quote', '"'],
		['quote then backslash', '"' + BS],
		['two backslashes', BS + BS],
		['backslash text backslash', 'a' + BS + 'b' + BS],
		['backslash quote text', BS + '"text'],
	])('round-trips %s through quote → strip', (_label, original) => {
		expect(stripOuterQuotes(quoteDNSString(original))).toBe(original);
	});
});

describe('TXT record edit round-trip (fieldsFromRecordData → buildRecordData)', () => {
	it('preserves a TXT value containing backslash + quote', () => {
		const original = BS + '"';
		const stored = buildRecordData('TXT', { text: original });
		expect(stored).toEqual({ data: quoteDNSString(original) });

		// Re-opening the record in the editor must show the original text...
		const reopened = fieldsFromRecordData('TXT', (stored as { data: string }).data).text;
		expect(reopened).toBe(original);

		// ...and re-saving must reproduce the stored data byte-for-byte.
		const resaved = buildRecordData('TXT', { text: reopened });
		expect(resaved).toEqual({ data: quoteDNSString(original) });
	});

	it('preserves ordinary TXT, MX, and NAPTR values on edit round-trip', () => {
		const cases = [
			['TXT', '"hello world"'],
			['MX', '10 mail.example.com.'],
			['NAPTR', '100 10 "" "" "/.*' + BS + '.example' + BS + '.com/" sip.example.com.'],
		] as const;
		for (const [type, data] of cases) {
			const fields = fieldsFromRecordData(type, data);
			expect(buildRecordData(type, fields)).toEqual({ data });
		}
	});
});
