import dns from "node:dns/promises";
import net from "node:net";

function ipv4ToNumber(address) {
  const octets = address.split(".").map(Number);
  return (((octets[0] * 256 + octets[1]) * 256 + octets[2]) * 256 + octets[3]) >>> 0;
}

function inV4Range(address, base, bits) {
  const mask = bits === 0 ? 0 : (0xffffffff << (32 - bits)) >>> 0;
  return (ipv4ToNumber(address) & mask) === (ipv4ToNumber(base) & mask);
}

const BLOCKED_V4 = [
  ["0.0.0.0", 8], ["10.0.0.0", 8], ["100.64.0.0", 10],
  ["127.0.0.0", 8], ["169.254.0.0", 16], ["172.16.0.0", 12],
  ["192.0.0.0", 24], ["192.0.2.0", 24], ["192.88.99.0", 24],
  ["192.168.0.0", 16], ["198.18.0.0", 15], ["198.51.100.0", 24],
  ["203.0.113.0", 24], ["224.0.0.0", 4], ["240.0.0.0", 4],
];

function ipv6Words(address) {
  let input = address.toLowerCase().split("%")[0];
  if (input.includes(".")) {
    const lastColon = input.lastIndexOf(":");
    const v4 = input.slice(lastColon + 1);
    if (net.isIP(v4) !== 4) return null;
    const n = ipv4ToNumber(v4);
    input = `${input.slice(0, lastColon)}:${((n >>> 16) & 0xffff).toString(16)}:${(n & 0xffff).toString(16)}`;
  }
  const halves = input.split("::");
  if (halves.length > 2) return null;
  const left = halves[0] ? halves[0].split(":") : [];
  const right = halves.length === 2 && halves[1] ? halves[1].split(":") : [];
  const zeros = halves.length === 2 ? 8 - left.length - right.length : 0;
  const words = [...left, ...Array(zeros).fill("0"), ...right].map((word) => Number.parseInt(word, 16));
  return words.length === 8 && words.every((word) => Number.isInteger(word) && word >= 0 && word <= 0xffff) ? words : null;
}

export function isPublicAddress(address) {
  const family = net.isIP(address);
  if (family === 4) return !BLOCKED_V4.some(([base, bits]) => inV4Range(address, base, bits));
  if (family !== 6) return false;

  const words = ipv6Words(address);
  if (!words) return false;
  const isMappedV4 = words.slice(0, 5).every((word) => word === 0) && words[5] === 0xffff;
  if (isMappedV4) {
    const mapped = `${words[6] >>> 8}.${words[6] & 255}.${words[7] >>> 8}.${words[7] & 255}`;
    return isPublicAddress(mapped);
  }

  // Accept only global unicast space, and exclude special-purpose/documentation ranges.
  if ((words[0] & 0xe000) !== 0x2000) return false;
  if (words[0] === 0x2001 && (words[1] === 0x0db8 || (words[1] & 0xfff0) === 0x0010)) return false;
  if (words[0] === 0x2002) return false;
  if (words[0] === 0x2001 && words[1] === 0) return false;
  return true;
}

export function validateTarget(input) {
  if (typeof input !== "string" || input.length === 0 || input.length > 2048) {
    throw new Error("Enter a URL no longer than 2,048 characters.");
  }
  let url;
  try {
    url = new URL(input);
  } catch {
    throw new Error("Enter a valid absolute website URL.");
  }
  if (!["http:", "https:"].includes(url.protocol)) throw new Error("Only public HTTP and HTTPS URLs can be analyzed.");
  if (url.username || url.password) throw new Error("URLs containing credentials are not allowed.");
  if (url.port && !((url.protocol === "http:" && url.port === "80") || (url.protocol === "https:" && url.port === "443"))) {
    throw new Error("Only the standard HTTP and HTTPS ports are allowed.");
  }
  const hostname = url.hostname.toLowerCase().replace(/^\[|\]$/g, "").replace(/\.$/, "");
  if (!hostname || hostname === "localhost" || hostname.endsWith(".localhost") ||
      hostname.endsWith(".local") || hostname.endsWith(".internal") ||
      hostname.endsWith(".test") || !hostname.includes(".") && net.isIP(hostname) === 0) {
    throw new Error("Local, internal, and single-label hostnames are not allowed.");
  }
  if (net.isIP(hostname) && !isPublicAddress(hostname)) throw new Error("The URL must resolve to a publicly routable address.");
  url.hash = "";
  return url;
}

export async function resolvePublicHost(hostname) {
  const literal = hostname.replace(/^\[|\]$/g, "");
  const literalFamily = net.isIP(literal);
  if (literalFamily) {
    if (!isPublicAddress(literal)) throw new Error("The target address is not publicly routable.");
    return [{ address: literal, family: literalFamily }];
  }

  let addresses;
  try {
    addresses = await dns.lookup(literal, { all: true, verbatim: true });
  } catch {
    throw new Error("DNS lookup failed for the target host.");
  }
  if (addresses.length === 0) throw new Error("DNS returned no addresses for the target host.");
  if (addresses.some(({ address }) => !isPublicAddress(address))) {
    throw new Error("The target host resolves to a non-public address; analysis was blocked.");
  }
  return addresses;
}
