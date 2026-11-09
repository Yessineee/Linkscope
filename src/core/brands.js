export const BRANDS = {
  google: ['google.com'], youtube: ['youtube.com', 'youtu.be'],
  facebook: ['facebook.com', 'fb.com'], instagram: ['instagram.com'],
  twitter: ['twitter.com', 't.co'], x: ['x.com'],
  whatsapp: ['whatsapp.com', 'whatsapp.net'], wikipedia: ['wikipedia.org'],
  amazon: ['amazon.com'], yahoo: ['yahoo.com'],
  reddit: ['reddit.com', 'redd.it'], tiktok: ['tiktok.com'],
  linkedin: ['linkedin.com', 'lnkd.in'], netflix: ['netflix.com'],
  bing: ['bing.com'], pinterest: ['pinterest.com'], twitch: ['twitch.tv'],
  microsoft: ['microsoft.com', 'microsoftonline.com'],
  apple: ['apple.com'], spotify: ['spotify.com'],
  discord: ['discord.com', 'discord.gg'], ebay: ['ebay.com'],
  office: ['office.com'], live: ['live.com'], cloudflare: ['cloudflare.com'],
  github: ['github.com'], gitlab: ['gitlab.com'],
  stackoverflow: ['stackoverflow.com'], zoom: ['zoom.us', 'zoom.com'],
  dropbox: ['dropbox.com'], salesforce: ['salesforce.com'],
  adobe: ['adobe.com'], paypal: ['paypal.com'], shopify: ['shopify.com'],
  wordpress: ['wordpress.com', 'wordpress.org'], quora: ['quora.com'],
  imdb: ['imdb.com'], walmart: ['walmart.com'], target: ['target.com'],
  bestbuy: ['bestbuy.com'], etsy: ['etsy.com'], craigslist: ['craigslist.org'],
  booking: ['booking.com'], airbnb: ['airbnb.com'], uber: ['uber.com'],
  lyft: ['lyft.com'], doordash: ['doordash.com'],
  tripadvisor: ['tripadvisor.com'], expedia: ['expedia.com'],
  cnn: ['cnn.com'], bbc: ['bbc.com', 'bbc.co.uk'], nytimes: ['nytimes.com'],
  forbes: ['forbes.com'], medium: ['medium.com'], wsj: ['wsj.com'],
  theguardian: ['theguardian.com'], espn: ['espn.com'], nba: ['nba.com'],
  nfl: ['nfl.com'], fifa: ['fifa.com'], chase: ['chase.com'],
  wellsfargo: ['wellsfargo.com'], bankofamerica: ['bankofamerica.com'],
  citibank: ['citibank.com', 'citi.com'], hsbc: ['hsbc.com'],
  barclays: ['barclays.com', 'barclays.co.uk'],
  americanexpress: ['americanexpress.com'], visa: ['visa.com'],
  mastercard: ['mastercard.com'], coinbase: ['coinbase.com'],
  binance: ['binance.com'], kraken: ['kraken.com'],
  robinhood: ['robinhood.com'], fidelity: ['fidelity.com'],
  schwab: ['schwab.com'], samsung: ['samsung.com'], sony: ['sony.com'],
  lg: ['lg.com'], dell: ['dell.com'], hp: ['hp.com'], lenovo: ['lenovo.com'],
  intel: ['intel.com'], nvidia: ['nvidia.com'], tesla: ['tesla.com'],
  spacex: ['spacex.com'], openai: ['openai.com', 'chatgpt.com'],
  anthropic: ['anthropic.com', 'claude.ai'], slack: ['slack.com'],
  notion: ['notion.so', 'notion.com'], figma: ['figma.com'],
  canva: ['canva.com'], atlassian: ['atlassian.com'], jira: ['atlassian.com'],
  trello: ['trello.com'], asana: ['asana.com'], monday: ['monday.com'],
  hubspot: ['hubspot.com'], mailchimp: ['mailchimp.com'],
  stripe: ['stripe.com'], square: ['squareup.com'], venmo: ['venmo.com'],
  zelle: ['zellepay.com'], indeed: ['indeed.com'],
  glassdoor: ['glassdoor.com'], monster: ['monster.com'],
  ziprecruiter: ['ziprecruiter.com'], coursera: ['coursera.org'],
  udemy: ['udemy.com'], khanacademy: ['khanacademy.org'],
  duolingo: ['duolingo.com'], gmail: ['gmail.com'], icloud: ['icloud.com'],
  protonmail: ['protonmail.com', 'proton.me'], outlook: ['outlook.com'],
  wetransfer: ['wetransfer.com'], telegram: ['telegram.org', 't.me'],
  signal: ['signal.org'], snapchat: ['snapchat.com'], flickr: ['flickr.com'],
  vimeo: ['vimeo.com'],
}

export const TOP_GLOBAL_DOMAINS = new Set(Object.keys(BRANDS))
export const ALLOWED_DOMAINS = new Set(Object.values(BRANDS).flat())

// Too short or ambiguous for edit-distance comparison (from the old list).
export const TYPO_EXCLUDED = new Set([
  'x', 'lg', 'hp', 'bbc', 'cnn', 'wsj', 'nba', 'nfl', 'fifa', 'bing',
  'dell', 'espn', 'etsy', 'imdb', 'jira', 'live', 'lyft', 'sony', 'uber',
  'visa', 'zoom', 'office', 'target', 'square', 'medium', 'monday',
  'indeed', 'intel', 'monster', 'booking',
])

// Ordinary English words: a label like "monday.org" is probably innocent.
export const WORD_BRANDS = new Set([
  'office', 'target', 'live', 'medium', 'monday', 'square', 'indeed',
  'monster', 'booking', 'signal',
])

// Brands that really operate on country domains (google.fr, amazon.co.uk).
export const COUNTRY_VARIANT_BRANDS = new Set([
  'google', 'amazon', 'microsoft', 'apple', 'ebay', 'yahoo', 'paypal',
  'netflix', 'airbnb', 'samsung', 'lg', 'dell', 'hp', 'lenovo',
])

// Deliberately explicit: many ccTLDs (.io .ai .tk .me) are not "country" in practice.
export const COMMON_COUNTRY_CODES = new Set([
  'tn', 'fr', 'de', 'uk', 'es', 'it', 'nl', 'be', 'ch', 'at', 'se', 'no',
  'dk', 'fi', 'pl', 'pt', 'ie', 'ca', 'us', 'au', 'nz', 'jp', 'kr', 'in',
  'br', 'mx', 'ar', 'za', 'ae', 'sa', 'eg', 'ma', 'dz', 'tr',
])

export const SUSPICIOUS_WORDS = new Set([
  'login', 'signin', 'verify', 'verification', 'secure', 'security',
  'account', 'update', 'confirm', 'confirmation', 'password', 'billing',
  'payment', 'support', 'service', 'recover', 'recovery', 'unlock',
  'suspended', 'authenticate', 'auth', 'validate', 'validation', 'alert',
  'restore', 'reactivate',
])

export const KNOWN_REDIRECT_SERVICES = new Set([
  't.co', 'bit.ly', 'tinyurl.com', 'goo.gl', 'ow.ly',
  'buff.ly', 'is.gd', 'rebrand.ly', 'lnkd.in', 'youtu.be',
])


// Hosts where each path belongs to a different owner (forms, sites, shared files, channels).
// An entry is either a whole host ("sites.google.com") or one part of a host ("docs.google.com/forms").
// Written from memory: verify each entry before relying on the list.
export const MULTI_TENANT_PATHS = [
  'docs.google.com/forms',
  'sites.google.com',
  'forms.gle',
  'storage.googleapis.com',
  'firebasestorage.googleapis.com',
  'onedrive.live.com',
  '1drv.ms',
  'dropbox.com/s',
  'dropbox.com/scl',
  'notion.so',
  'linktr.ee',
  't.me',
]