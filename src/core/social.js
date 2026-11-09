// Recognises social media, messaging and code-hosting profiles from URLs.
//
// Rule: { platform, host: RegExp on the bare host, path: RegExp on the pathname
// (group 1 = handle), reserved: paths that aren't profiles }.

const RESERVED_COMMON = new Set([
  "share", "sharer", "sharer.php", "intent", "home", "login", "signup", "search", "explore", "hashtag", "settings",
  "about", "help", "privacy", "terms", "policies", "legal", "watch", "embed", "plugins", "dialog", "tr", "i", "p",
  "status", "messages", "notifications", "events", "groups", "pages", "jobs", "business", "ads", "developers",
  "oauth", "authorize", "web", "feed", "hashtags", "reel", "reels", "stories", "tv", "direct", "accounts", "en",
  "shareArticle", "sharing", "results", "playlist", "channel", "user", "c", "redirect", "l.php", "photo", "photos",
  "video", "videos", "story.php", "permalink.php", "profile.php", "trending", "topics", "lists", "public", "s"
]);

const RULES = [
  { platform: "X / Twitter", host: /^(www\.|mobile\.)?(twitter|x)\.com$/, path: /^\/@?([A-Za-z0-9_]{1,15})\/?$/ },
  { platform: "Facebook", host: /^(www\.|m\.|web\.)?(facebook|fb)\.com$/, path: /^\/(?:pg\/)?([A-Za-z0-9.\-]{2,80})\/?$/ },
  { platform: "Facebook", host: /^(www\.|m\.)?facebook\.com$/, path: /^\/profile\.php$/, query: "id" },
  { platform: "Instagram", host: /^(www\.)?instagram\.com$/, path: /^\/([A-Za-z0-9_.]{1,30})\/?$/ },
  { platform: "Threads", host: /^(www\.)?threads\.(net|com)$/, path: /^\/@([A-Za-z0-9_.]{1,30})\/?$/ },
  { platform: "LinkedIn", host: /^([a-z]{2,3}\.|www\.)?linkedin\.com$/, path: /^\/(?:in|pub)\/([^/?#]{2,100})\/?$/ },
  { platform: "LinkedIn company", host: /^([a-z]{2,3}\.|www\.)?linkedin\.com$/, path: /^\/(?:company|school|showcase)\/([^/?#]{2,100})\/?/ },
  { platform: "YouTube", host: /^(www\.|m\.)?youtube\.com$/, path: /^\/(@[A-Za-z0-9_.\-]{2,60}|(?:channel|c|user)\/[A-Za-z0-9_\-]{2,60})\/?/ },
  { platform: "TikTok", host: /^(www\.)?tiktok\.com$/, path: /^\/@([A-Za-z0-9_.]{2,24})\/?/ },
  { platform: "GitHub", host: /^(www\.)?github\.com$/, path: /^\/([A-Za-z0-9](?:[A-Za-z0-9-]{0,38}))\/?(?:[A-Za-z0-9_.\-]+\/?)?$/,
    reserved: new Set(["features", "pricing", "marketplace", "sponsors", "topics", "collections", "orgs", "apps", "enterprise", "team", "customer-stories", "security", "readme", "site", "contact", "new", "codespaces", "copilot", "solutions", "resources"]) },
  { platform: "GitLab", host: /^(www\.)?gitlab\.com$/, path: /^\/([A-Za-z0-9_.\-]{2,60})\/?$/ },
  { platform: "Bitbucket", host: /^(www\.)?bitbucket\.org$/, path: /^\/([A-Za-z0-9_\-]{2,60})\/?$/ },
  { platform: "Reddit", host: /^(www\.|old\.|new\.)?reddit\.com$/, path: /^\/(?:u|user)\/([A-Za-z0-9_\-]{3,20})\/?/ },
  { platform: "Subreddit", host: /^(www\.|old\.|new\.)?reddit\.com$/, path: /^\/r\/([A-Za-z0-9_]{2,21})\/?/ },
  { platform: "Telegram", host: /^(t\.me|telegram\.me|telegram\.dog)$/, path: /^\/(?:s\/)?([A-Za-z0-9_]{5,32}|\+[A-Za-z0-9_\-]{10,}|joinchat\/[A-Za-z0-9_\-]+)\/?$/ },
  { platform: "WhatsApp", host: /^(wa\.me|api\.whatsapp\.com|chat\.whatsapp\.com)$/, path: /^\/(?:send\/?)?([0-9]{6,15}|[A-Za-z0-9]{16,})?\/?$/, query: "phone" },
  { platform: "Signal", host: /^signal\.(me|group)$/, path: /^\/(.*)$/ },
  { platform: "Discord", host: /^(www\.)?(discord\.gg|discord\.com|discordapp\.com)$/, path: /^\/(?:invite\/)?([A-Za-z0-9\-]{2,32})\/?$/ },
  { platform: "Mastodon / Fediverse", host: /./, path: /^\/@([A-Za-z0-9_]{1,30})(?:@[a-z0-9.\-]+)?\/?$/ },
  { platform: "Bluesky", host: /^bsky\.app$/, path: /^\/profile\/([A-Za-z0-9.\-:]{3,253})\/?$/ },
  { platform: "Pinterest", host: /^([a-z]{2}\.|www\.)?pinterest\.[a-z.]+$/, path: /^\/([A-Za-z0-9_]{3,30})\/?$/ },
  { platform: "Snapchat", host: /^(www\.)?snapchat\.com$/, path: /^\/(?:add|@)\/?([A-Za-z0-9_.\-]{3,15})\/?$/ },
  { platform: "Twitch", host: /^(www\.|m\.)?twitch\.tv$/, path: /^\/([A-Za-z0-9_]{4,25})\/?$/ },
  { platform: "Vimeo", host: /^(www\.)?vimeo\.com$/, path: /^\/([A-Za-z][A-Za-z0-9_]{2,40})\/?$/ },
  { platform: "Medium", host: /^(www\.)?medium\.com$/, path: /^\/@([A-Za-z0-9_.]{1,50})\/?/ },
  { platform: "Substack", host: /^([a-z0-9\-]+)\.substack\.com$/, hostHandle: true },
  { platform: "Tumblr", host: /^([a-z0-9\-]+)\.tumblr\.com$/, hostHandle: true },
  { platform: "VK", host: /^(www\.|m\.)?vk\.com$/, path: /^\/([A-Za-z0-9_.]{2,60})\/?$/ },
  { platform: "OK.ru", host: /^(www\.)?ok\.ru$/, path: /^\/(?:profile\/)?([A-Za-z0-9_.]{2,60})\/?$/ },
  { platform: "Weibo", host: /^(www\.)?weibo\.com$/, path: /^\/(?:u\/)?([A-Za-z0-9_]{2,60})\/?$/ },
  { platform: "Patreon", host: /^(www\.)?patreon\.com$/, path: /^\/([A-Za-z0-9_]{2,60})\/?$/ },
  { platform: "Ko-fi", host: /^(www\.)?ko-fi\.com$/, path: /^\/([A-Za-z0-9_]{2,60})\/?$/ },
  { platform: "Buy Me a Coffee", host: /^(www\.)?buymeacoffee\.com$/, path: /^\/([A-Za-z0-9_]{2,60})\/?$/ },
  { platform: "Linktree", host: /^(www\.)?linktr\.ee$/, path: /^\/([A-Za-z0-9_.]{2,60})\/?$/ },
  { platform: "Keybase", host: /^(www\.)?keybase\.io$/, path: /^\/([A-Za-z0-9_]{2,16})\/?$/ },
  { platform: "Behance", host: /^(www\.)?behance\.net$/, path: /^\/([A-Za-z0-9_\-]{2,60})\/?$/ },
  { platform: "Dribbble", host: /^(www\.)?dribbble\.com$/, path: /^\/([A-Za-z0-9_\-]{2,60})\/?$/ },
  { platform: "SoundCloud", host: /^(www\.|m\.)?soundcloud\.com$/, path: /^\/([A-Za-z0-9_\-]{2,60})\/?$/ },
  { platform: "Spotify", host: /^open\.spotify\.com$/, path: /^\/(?:user|artist)\/([A-Za-z0-9]{2,60})\/?$/ },
  { platform: "Steam", host: /^steamcommunity\.com$/, path: /^\/(?:id|profiles)\/([A-Za-z0-9_\-]{2,64})\/?$/ },
  { platform: "Stack Overflow", host: /^(www\.)?stackoverflow\.com$/, path: /^\/users\/(\d+(?:\/[A-Za-z0-9\-]+)?)\/?$/ },
  { platform: "Hacker News", host: /^news\.ycombinator\.com$/, path: /^\/user$/, query: "id" },
  { platform: "Xing", host: /^(www\.)?xing\.com$/, path: /^\/profile\/([A-Za-z0-9_]{2,60})\/?$/ },
  { platform: "Crunchbase", host: /^(www\.)?crunchbase\.com$/, path: /^\/(?:organization|person)\/([A-Za-z0-9\-]{2,100})\/?$/ },
  { platform: "AngelList / Wellfound", host: /^(www\.)?(angel\.co|wellfound\.com)$/, path: /^\/(?:u|company)\/([A-Za-z0-9\-]{2,100})\/?$/ },
  { platform: "Gravatar", host: /^([a-z]{2}\.)?gravatar\.com$/, path: /^\/([A-Za-z0-9_.\-]{2,60})\/?$/ },
  { platform: "Flickr", host: /^(www\.)?flickr\.com$/, path: /^\/(?:people|photos)\/([A-Za-z0-9@_\-]{2,60})\/?/ },
  { platform: "Tripadvisor", host: /^(www\.)?tripadvisor\.[a-z.]+$/, path: /^\/Profile\/([A-Za-z0-9_\-]{2,60})\/?$/ },
  { platform: "Yelp", host: /^(www\.)?yelp\.[a-z.]+$/, path: /^\/biz\/([A-Za-z0-9_\-]{2,120})\/?$/ },
  { platform: "Google Maps place", host: /^(www\.)?google\.[a-z.]+$|^maps\.google\.[a-z.]+$|^maps\.app\.goo\.gl$/, path: /^\/(?:maps\/place\/([^/]+)|([A-Za-z0-9]{10,}))/ },
  { platform: "Product Hunt", host: /^(www\.)?producthunt\.com$/, path: /^\/@([A-Za-z0-9_]{2,40})\/?$/ },
  { platform: "Kick", host: /^(www\.)?kick\.com$/, path: /^\/([A-Za-z0-9_]{3,25})\/?$/ },
  { platform: "Rumble", host: /^(www\.)?rumble\.com$/, path: /^\/(?:c|user)\/([A-Za-z0-9_\-]{2,60})\/?$/ },
  { platform: "Truth Social", host: /^(www\.)?truthsocial\.com$/, path: /^\/@([A-Za-z0-9_]{1,30})\/?$/ },
  { platform: "Gab", host: /^(www\.)?gab\.com$/, path: /^\/([A-Za-z0-9_]{2,30})\/?$/ },
  { platform: "Odysee", host: /^(www\.)?odysee\.com$/, path: /^\/(@[^/:]{2,60})/ },
  { platform: "Line", host: /^line\.me$/, path: /^\/(?:R\/)?ti\/p\/(~?[A-Za-z0-9_@\-]{2,60})\/?$/ },
  { platform: "Viber", host: /^(invite\.viber\.com|chats\.viber\.com)$/, path: /^\/(.+)$/ },
  { platform: "Skype", host: /^join\.skype\.com$/, path: /^\/(.+)$/ },
  { platform: "Calendly", host: /^calendly\.com$/, path: /^\/([A-Za-z0-9_\-]{2,60})\/?/ },
  { platform: "Amazon author/store", host: /^(www\.)?amazon\.[a-z.]+$/, path: /^\/(?:stores|author)\/([^/]{2,80})/ }
];

const KNOWN_SOCIAL_HOSTS = /(?:^|\.)(twitter|x|facebook|fb|instagram|threads|linkedin|youtube|tiktok|github|gitlab|bitbucket|reddit|pinterest|snapchat|twitch|vimeo|medium|tumblr|substack|vk|ok|weibo|patreon|ko-fi|buymeacoffee|linktr|keybase|behance|dribbble|soundcloud|spotify|steamcommunity|stackoverflow|xing|crunchbase|wellfound|angel|gravatar|flickr|bsky|discord|discordapp|telegram|signal|kick|rumble|truthsocial|gab|odysee|line|viber|skype|calendly)\.[a-z.]+$|^(t\.me|wa\.me|linktr\.ee|bsky\.app|discord\.gg)$/;

/**
 * Identify a social profile from a URL.
 * @returns {{platform:string, handle:string, url:string}|null}
 */
export function matchSocial(href) {
  let u;
  try {
    u = new URL(href);
  } catch {
    return null;
  }
  if (!/^https?:$/.test(u.protocol)) return null;
  const host = u.hostname.toLowerCase();
  const path = decodeURIComponent(u.pathname).replace(/\/+$/, "") || "/";
  for (const r of RULES) {
    const hm = r.host.exec(host);
    if (!hm) continue;
    // The generic fediverse rule (any host, "/@user") only applies to hosts that aren't known platforms.
    if (r.platform.startsWith("Mastodon") && KNOWN_SOCIAL_HOSTS.test(host)) continue;
    if (r.hostHandle) {
      if (["www", "api", "cdn", "static", "assets", "help", "support"].includes(hm[1])) continue;
      return { platform: r.platform, handle: hm[1], url: `https://${host}/` };
    }
    let handle = null;
    if (r.query && (!r.path || r.path.test(u.pathname))) {
      const pm = r.path && r.path.exec(u.pathname);
      handle = u.searchParams.get(r.query) || (pm && pm[1]) || null;
    } else if (r.path) {
      const pm = r.path.exec(path === "/" ? "/" : path);
      handle = pm && (pm[1] || pm[2]);
    }
    if (!handle) continue;
    const first = handle.split("/")[0].replace(/^@/, "");
    if (RESERVED_COMMON.has(first) || RESERVED_COMMON.has(first.toLowerCase()) || r.reserved?.has(first.toLowerCase())) continue;
    if (r.platform.startsWith("Mastodon")) handle = `@${handle}@${host}`;
    return { platform: r.platform, handle, url: `${u.origin}${u.pathname}${r.query ? u.search : ""}` };
  }
  return null;
}

/** Bare host is a known social/messaging platform (used for third-party classification). */
export const isSocialHost = (host) => KNOWN_SOCIAL_HOSTS.test(String(host).toLowerCase());
