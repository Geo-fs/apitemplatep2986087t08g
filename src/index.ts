import { Hono } from "hono";

type FeedItem = {
  title?: string;
  link?: string;
  pubDate?: string;
  summary?: string;
};

const app = new Hono();

/**
 * Minimal SSRF guard:
 * - blocks localhost + private IP ranges + metadata endpoints
 * - blocks non-http(s)
 */
function isUrlAllowed(raw: string): { ok: boolean; reason?: string } {
  let u: URL;
  try {
    u = new URL(raw);
  } catch {
    return { ok: false, reason: "Invalid URL" };
  }

  if (u.protocol !== "http:" && u.protocol !== "https:") {
    return { ok: false, reason: "Only http/https allowed" };
  }

  const host = u.hostname.toLowerCase();

  // Block obvious bad hosts
  const blockedHosts = new Set([
    "localhost",
    "0.0.0.0",
    "127.0.0.1",
    "::1",
    "169.254.169.254", // cloud metadata
    "metadata.google.internal",
  ]);
  if (blockedHosts.has(host)) {
    return { ok: false, reason: "Blocked host" };
  }

  // Block private IP ranges if hostname is an IP
  // (simple check; good enough for this use-case)
  const isIPv4 = /^(\d{1,3}\.){3}\d{1,3}$/.test(host);
  if (isIPv4) {
    const parts = host.split(".").map((n) => Number(n));
    const [a, b] = parts;

    const inRange =
      a === 10 ||
      (a === 172 && b >= 16 && b <= 31) ||
      (a === 192 && b === 168) ||
      a === 127 ||
      (a === 169 && b === 254);

    if (inRange) return { ok: false, reason: "Private IP blocked" };
  }

  return { ok: true };
}

function textOf(el?: Element | null): string | undefined {
  const t = el?.textContent?.trim();
  return t || undefined;
}

function firstLinkFromAtom(entry: Element): string | undefined {
  const links = Array.from(entry.getElementsByTagName("link"));
  // Prefer rel="alternate", otherwise first href
  for (const l of links) {
    const rel = (l.getAttribute("rel") || "").toLowerCase();
    const href = l.getAttribute("href") || "";
    if (href && (!rel || rel === "alternate")) return href;
  }
  return links[0]?.getAttribute("href") || undefined;
}

function parseRssOrAtom(xmlText: string): { feedTitle?: string; feedLink?: string; items: FeedItem[] } {
  const parser = new DOMParser();
  const doc = parser.parseFromString(xmlText, "text/xml");

  // Detect parser errors
  const parserErr = doc.getElementsByTagName("parsererror")[0];
  if (parserErr) {
    throw new Error("Failed to parse XML (not valid RSS/Atom?)");
  }

  const rssChannel = doc.getElementsByTagName("channel")[0];
  const atomFeed = doc.getElementsByTagName("feed")[0];

  const items: FeedItem[] = [];

  if (rssChannel) {
    const feedTitle = textOf(rssChannel.getElementsByTagName("title")[0]);
    const feedLink = textOf(rssChannel.getElementsByTagName("link")[0]);

    const rssItems = Array.from(doc.getElementsByTagName("item")).slice(0, 50);
    for (const it of rssItems) {
      const title = textOf(it.getElementsByTagName("title")[0]);
      const link = textOf(it.getElementsByTagName("link")[0]);
      const pubDate = textOf(it.getElementsByTagName("pubDate")[0]);
      const summary =
        textOf(it.getElementsByTagName("description")[0]) ||
        textOf(it.getElementsByTagName("content:encoded")[0]);

      items.push({ title, link, pubDate, summary });
    }

    return { feedTitle, feedLink, items };
  }

  if (atomFeed) {
    const feedTitle = textOf(atomFeed.getElementsByTagName("title")[0]);

    // Atom feed link (try first link)
    const feedLinkEl = atomFeed.getElementsByTagName("link")[0];
    const feedLink = feedLinkEl?.getAttribute("href") || undefined;

    const entries = Array.from(atomFeed.getElementsByTagName("entry")).slice(0, 50);
    for (const e of entries) {
      const title = textOf(e.getElementsByTagName("title")[0]);
      const link = firstLinkFromAtom(e);
      const pubDate =
        textOf(e.getElementsByTagName("updated")[0]) ||
        textOf(e.getElementsByTagName("published")[0]);
      const summary =
        textOf(e.getElementsByTagName("summary")[0]) ||
        textOf(e.getElementsByTagName("content")[0]);

      items.push({ title, link, pubDate, summary });
    }

    return { feedTitle, feedLink, items };
  }

  throw new Error("Not RSS or Atom");
}

app.get("/health", (c) => c.json({ ok: true }));

app.get("/rss", async (c) => {
  const url = c.req.query("url");
  if (!url) return c.json({ error: "Missing ?url=" }, 400);

  const allowed = isUrlAllowed(url);
  if (!allowed.ok) return c.json({ error: allowed.reason || "URL blocked" }, 400);

  // Cache key includes the feed URL
  const cacheKey = new Request(c.req.url, c.req.raw);

  // Fetch with Cloudflare edge caching enabled
  const resp = await fetch(url, {
    headers: {
      "User-Agent": "Mozilla/5.0 (compatible; FeedFetcher/1.0; +https://workers.cloudflare.com/)",
      "Accept": "application/rss+xml, application/atom+xml, application/xml, text/xml;q=0.9, */*;q=0.8",
    },
    cf: {
      cacheEverything: true,
      cacheTtl: 120, // 2 minutes; adjust if you want
    } as any,
  });

  if (!resp.ok) {
    return c.json({ error: `Upstream error ${resp.status}` }, 502);
  }

  const contentType = resp.headers.get("content-type") || "";
  const bodyText = await resp.text();

  // If it’s already JSON, just pass it through as-is (nice for JSON APIs)
  if (contentType.includes("application/json") || bodyText.trim().startsWith("{") || bodyText.trim().startsWith("[")) {
    try {
      const json = JSON.parse(bodyText);
      return c.json({ source: url, type: "json", data: json }, 200, {
        "Cache-Control": "public, max-age=120",
      });
    } catch {
      // fall through to XML parsing attempt
    }
  }

  try {
    const parsed = parseRssOrAtom(bodyText);
    return c.json(
      {
        source: url,
        type: "rss",
        ...parsed,
      },
      200,
      {
        "Cache-Control": "public, max-age=120",
      }
    );
  } catch (e: any) {
    return c.json(
      {
        error: "Could not parse feed",
        hint: "Make sure the URL is RSS/Atom XML or JSON.",
        details: String(e?.message || e),
      },
      400
    );
  }
});

export default app;
