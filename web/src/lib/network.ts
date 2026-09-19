// Client-side checks for IP addresses and CIDR networks. The server is the
// authority (it normalizes and rejects invalid entries); these only give
// immediate feedback in forms.

function isIPv4(value: string): boolean {
	const parts = value.split('.');
	return (
		parts.length === 4 &&
		parts.every((p) => /^\d{1,3}$/.test(p) && Number(p) <= 255 && (p === '0' || !p.startsWith('0')))
	);
}

function isIPv6(value: string): boolean {
	if (!/^[0-9a-fA-F:.]+$/.test(value) || !value.includes(':')) return false;
	const doubleColons = value.split('::').length - 1;
	if (doubleColons > 1) return false;
	let groups = value.split(':');
	const last = groups[groups.length - 1];
	let extraGroups = 0;
	if (last.includes('.')) {
		if (!isIPv4(last)) return false;
		groups = groups.slice(0, -1);
		extraGroups = 2;
	}
	const nonEmpty = groups.filter((g) => g !== '');
	if (!nonEmpty.every((g) => /^[0-9a-fA-F]{1,4}$/.test(g))) return false;
	const total = nonEmpty.length + extraGroups;
	return doubleColons === 1 ? total < 8 : total === 8;
}

/** Reports whether value is a single IP address or a CIDR network. */
export function isIPOrCIDR(value: string): boolean {
	const v = value.trim();
	if (!v) return false;
	const [addr, prefix, ...rest] = v.split('/');
	if (rest.length > 0) return false;
	const v4 = isIPv4(addr);
	const v6 = !v4 && isIPv6(addr);
	if (!v4 && !v6) return false;
	if (prefix === undefined) return true;
	if (!/^\d{1,3}$/.test(prefix)) return false;
	return Number(prefix) <= (v4 ? 32 : 128);
}

/** Reports whether a network admits every IPv4 or IPv6 client. */
export function isEverywhere(value: string): boolean {
	const v = value.trim();
	return v === '0.0.0.0/0' || v === '::/0';
}
