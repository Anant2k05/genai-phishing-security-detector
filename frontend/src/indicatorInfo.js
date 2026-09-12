// Plain-language "why this matters" text for each indicator id.
// Kept separate from the components so the copy is easy to review/edit on its own.

export const IMPACT_TEXT = {
  urgency: "Creates time pressure so the recipient acts before verifying the request independently.",
  threat: "Uses fear of losing account access to push a fast, unchecked reaction.",
  password_request: "Legitimate services never ask you to type or send your password by email or message.",
  otp_request: "OTPs and verification codes are meant to stay private; sharing them hands over account access.",
  banking_request: "Requests for card or account numbers are a direct attempt at financial fraud.",
  payment_request: "Asking for upfront payment or a 'fee' is a common advance-fee scam pattern.",
  attachment: "Unexpected attachments are a common malware delivery method.",
  verification: "Fake 'verify your account' prompts are used to harvest login credentials.",
  cta: "Generic 'click here' phrasing is used to move you to a lookalike site quickly.",
  bypass_security: "Asking to disable security tools or install remote-access software is a major red flag.",
  tech_support: "Classic tech-support scam pattern: manufacture a fake problem, then ask for remote access or payment.",
  reward: "Unexpected prizes are used to lower suspicion before asking for personal or financial details.",
  emotional: "Appeals to urgency or secrecy discourage the recipient from checking with someone else first.",
  impersonation: "References a real brand to borrow its trust, without confirming the message actually came from it.",
  generic_greeting: "Legitimate account-related emails usually address you by name, not a generic title.",
  domain_mismatch: "The linked/sender domain doesn't match the brand mentioned in the message -- a lookalike-domain trick.",
  grammar_anomaly: "Unusual formatting (excessive caps, punctuation, or slang) is common in mass-sent scam messages.",
  http_scheme: "Unencrypted HTTP connections can be intercepted; legitimate login pages use HTTPS.",
  ip_host: "Legitimate services are almost never linked to by raw IP address.",
  excessive_subdomains: "Long subdomain chains are often used to make a URL look more official than it is.",
  long_url: "Excessive length can be used to hide the real destination or bury it after decoy text.",
  url_encoding: "Encoded characters can disguise the real destination from a quick visual check.",
  at_symbol: "Everything before an '@' in a URL is ignored by the browser -- text before it can be fake.",
  suspicious_keywords: "Keywords like 'login' or 'verify' in the path are used to make a link look account-related.",
  suspicious_tld: "This top-level domain is inexpensive and commonly abused for short-lived scam sites.",
  brand_lookalike: "The domain is built to resemble a trusted brand without actually being that brand's domain.",
  shortener: "Shortened links hide the real destination until after you click.",
  malformed: "The submitted text could not be parsed as a valid URL.",
};

export function getImpactText(id) {
  return IMPACT_TEXT[id] || "This pattern is commonly seen in phishing and social-engineering messages.";
}
