// A de-duplicating collection of indicators (the things an investigator pivots
// on: emails, domains, IPs, tracker IDs...). Every analysis module adds to one
// bag so the UI, the exporters and the correlation index all see one list.

/** Indicator types and their display labels. Order = display order. */
export const INDICATOR_TYPES = {
  domain: "Domain",
  host: "Hostname",
  url: "URL",
  ip: "IP address",
  email: "Email",
  phone: "Phone",
  social: "Social profile",
  handle: "Handle / username",
  crypto: "Crypto wallet",
  onion: "Onion / I2P service",
  coordinates: "Coordinates",
  address: "Postal address",
  tracker: "Tracking / ad ID",
  verification: "Site verification token",
  favicon: "Favicon hash",
  asn: "ASN",
  hash: "File hash",
  cve: "CVE",
  iban: "IBAN",
  business_id: "Business / VAT ID",
  person: "Person name",
  organization: "Organization",
  bucket: "Cloud storage bucket",
  api_key_public: "Public API key / client ID"
};

/** Normalised identity of an indicator value, for de-duplication and correlation. */
export function indicatorKey(type, value) {
  const v = String(value).trim();
  switch (type) {
    case "email":
    case "domain":
    case "host":
    case "onion":
    case "handle":
    case "bucket":
      return v.toLowerCase();
    case "phone":
      return v.replace(/[^\d+]/g, "");
    case "iban":
    case "business_id":
      return v.replace(/\s+/g, "").toUpperCase();
    case "crypto":
      return /^(0x|bc1|ltc1|tb1)/i.test(v) ? v.toLowerCase() : v;
    case "url":
      return v.replace(/#.*$/, "");
    default:
      return v;
  }
}

export class IndicatorBag {
  constructor() {
    /** @type {Map<string, any>} */
    this.map = new Map();
  }

  /**
   * @param {string} type    key of INDICATOR_TYPES
   * @param {string} value
   * @param {object} [o]
   * @param {string} [o.source]   where it was found ("text", "link", "script", "meta", "dns"...)
   * @param {string} [o.context]  surrounding text
   * @param {string} [o.label]    sub-type ("Bitcoin", "Google Analytics 4", "Instagram"...)
   * @param {object} [o.extra]    any additional structured data
   * @param {string} [o.confidence] "high" | "medium" | "low"
   */
  add(type, value, o = {}) {
    if (value == null || value === "") return null;
    value = String(value).trim();
    const key = `${type}|${indicatorKey(type, value)}`;
    let ind = this.map.get(key);
    if (!ind) {
      ind = { type, value, label: o.label || null, count: 0, sources: [], contexts: [], extra: o.extra ? { ...o.extra } : {}, confidence: o.confidence || "high" };
      this.map.set(key, ind);
    } else if (o.extra) {
      Object.assign(ind.extra, o.extra);
    }
    ind.count++;
    if (o.label && !ind.label) ind.label = o.label;
    if (o.source && !ind.sources.includes(o.source)) ind.sources.push(o.source);
    if (o.context && ind.contexts.length < 3 && !ind.contexts.includes(o.context)) ind.contexts.push(o.context);
    // Seeing something in several places raises confidence.
    if (o.confidence === "high" || (ind.confidence === "low" && ind.sources.length > 1)) ind.confidence = "high";
    else if (o.confidence === "medium" && ind.confidence === "low") ind.confidence = "medium";
    return ind;
  }

  has(type, value) {
    return this.map.has(`${type}|${indicatorKey(type, value)}`);
  }

  list() {
    const order = Object.keys(INDICATOR_TYPES);
    return [...this.map.values()].sort((a, b) => order.indexOf(a.type) - order.indexOf(b.type) || b.count - a.count || a.value.localeCompare(b.value));
  }

  ofType(type) {
    return this.list().filter((i) => i.type === type);
  }
}
