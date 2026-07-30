# Selector Review Log

Generated 2026-07-29 via `batch_inspect.py` + manual candidate review.

---

## RESOLVED — type changed to `html`

### AFINE
- **Selector:** `div.blog-post2-related_item.w-dyn-item`
- **Confidence:** high
- **Reason:** Webflow dynamic-list item, 10 hits, sample link `https://afine.com/blogs/stealing-passwords-via-html-injection-under-a-strict-csp` — real article slug.

---

### Datadog Security Labs
- **Selector:** `article.hit-flex`
- **Confidence:** high
- **Reason:** Algolia InfiniteHits article element, 8 hits, sample link `https://securitylabs.datadoghq.com/articles/detection-primitives-for-ebpf-rootkits/` — real article.

---

### Netcraft
- **Selector:** `div.framer-1wk7xcp-container`
- **Confidence:** high
- **Reason:** Framer post container, 10 hits, sample link `https://www.netcraft.com/blog/rise-of-ai-vibe-coding-and-new-cyber-threats` — real blog post.

---

### CISA News
- **Selector:** `article.is-promoted.c-teaser.c-teaser--horizontal`
- **Confidence:** high
- **Reason:** CISA teaser article card, 10 hits, sample link `https://www.cisa.gov/news-events/news/cisa-joins-australia-...` — real news article.

---

### CISA Alerts
- **Selector:** `article.is-promoted.c-teaser.c-teaser--horizontal`
- **Confidence:** high
- **Reason:** Same CISA teaser pattern on the filtered advisories URL, 10 hits, sample link `https://www.cisa.gov/news-events/alerts/2026/07/27/cisa-adds-two-known-exploited-vulnerabilities-catalog` — real alert.

---

### CISA Cybersecurity Advisories
- **Selector:** `article.is-promoted.c-teaser.c-teaser--horizontal`
- **Confidence:** high
- **Reason:** Same CISA teaser card on the broad advisories page, 10 hits, sample link `https://www.cisa.gov/resources-tools/resources/ci-fortify-advice-isolating-vital-systems` — real resource link.

---

### Cleafy
- **Selector:** `div.card-newsroom.lab.w-dyn-item`
- **Confidence:** high
- **Reason:** Webflow dyn-item specific to labs content, 9 hits, sample link `https://www.cleafy.com/cleafy-labs/nfc-relay-goes-local-...` — real lab article.

---

### Threatray
- **Selector:** `div.blog_item.w-dyn-item`
- **Confidence:** high
- **Reason:** Webflow blog dyn-item, 6 hits, sample link `https://www.threatray.com/blog/kuinaextractor-six-months-...` — real blog post.

---

### Splunk - Security Blog
- **Selector:** `div.article-list-card`
- **Confidence:** high
- **Reason:** Splunk article card element, 9 hits, sample link `https://www.splunk.com/en_us/blog/security/phantom-stealer-shellcode-steganography-credential-theft.html` — real security post.

---

### Hunt.io
- **Selector:** `div.framer-1409ko9`
- **Confidence:** high
- **Reason:** Framer post wrapper, 6 hits, sample link `https://hunt.io/blog/flying-eagle-android-rat-170-servers-night-dragon` — real blog post.

---

### IBM X-Force
- **Selector:** `div.horizontal-media-group__item`
- **Confidence:** high
- **Reason:** IBM media-group item, 15 hits, sample link `https://www.ibm.com/think/x-force/The-front-of-the-cyber-kill-chain-just-moved` — real X-Force article.

---

### Forcepoint
- **Selector:** `div.px-5.pt-5`
- **Confidence:** high
- **Reason:** X-Labs blog card, 10 hits, sample link `https://www.forcepoint.com/blog/x-labs/litellm-supply-chain-attack-teampcp` — real X-Labs post.

---

### Intezer
- **Selector:** `div.blogbodycard.w-dyn-item`
- **Confidence:** high
- **Reason:** Webflow blog card dyn-item, 15 hits, sample link `https://intezer.com/blog/intezer-org-brain` — real blog post.

---

### NCC Group
- **Selector:** `div.glide__slide.c-in__slide`
- **Confidence:** high
- **Reason:** Glide carousel research slides, 11 hits, sample link `https://www.nccgroup.com/research/what-the-13-looks-like-a-case-study/` — real research article.

---

### Guardio
- **Selector:** `div.blog_card.w-dyn-item`
- **Confidence:** high
- **Reason:** Webflow blog card dyn-item, 33 hits, sample link `https://guard.io/labs/hermeticreader-...` — real labs article. High count expected on a prolific blog.

---

### PT Security
- **Selector:** `article.ArticleList_list-item__8okkz.ArticleList_bordered__BOMAh`
- **Confidence:** high
- **Reason:** PT ESC article list item, 10 hits, sample link `https://global.ptsecurity.com/en/research/analytics/an-arms-race-...` — real analytics article.

---

### Top10VPN
- **Selector:** `article.jsx-1132817740.card.card-single`
- **Confidence:** high
- **Reason:** React article card, 12 hits, sample link `https://www.top10vpn.com/research/vpn-demand-statistics/` — real research article.

---

### Trend Micro
- **Selector:** `div.grid-content`
- **Confidence:** high
- **Reason:** Research grid card, 10 hits, sample link `https://www.trendmicro.com/en_us/research/26/g/autonomous-ransomware.html` — real research post.

---

### TRM Labs
- **Selector:** `div.post-item.w-dyn-item`
- **Confidence:** high
- **Reason:** Webflow blog post dyn-item, 6 hits, sample link `https://www.trmlabs.com/resources/blog/meet-the-agent-...` — real blog post.

---

### Sekoia
- **Selector:** `div.blog-list_item.w-dyn-item`
- **Confidence:** high
- **Reason:** Webflow blog list dyn-item, 16 hits, sample link `https://www.sekoia.com/blog/the-best-of-cloud-...` — real blog post.

---

### Koi Security
- **Selector:** `div.posts_item.all.w-dyn-item`
- **Confidence:** high
- **Reason:** Webflow posts dyn-item, 55 hits, sample link `https://www.koi.ai/blog/open-sesame-...` — real blog post.

---

### Driftnet
- **Selector:** `div.MuiPaper-root.MuiPaper-elevation.MuiPaper-rounded`
- **Confidence:** medium
- **Reason:** Material UI Paper card, 3 hits, sample link `https://driftnet.io/blog/driftnet-query-language-announcement` — real post. Low count (small blog), but MUI Paper is generic so watch for false matches.

---

### Bitdefender (blog, html_TODO entry)
- **Selector:** `div.tw-mb-12.tw-flex-wrap.tw-items-center`
- **Confidence:** medium
- **Reason:** Tailwind flex card, 4 hits, sample link `https://www.bitdefender.com/en-us/blog/hotforsecurity/us-cyberscams-visa-restrictions` — real blog post. First `a` inside may be a category tag link; verify scraper picks up the article link not the category filter.

---

## UNRESOLVED — remain `html_TODO`

### GetSafety
- **Confidence:** low
- **Reason:** Only 1 candidate (`ul.space-y-2`, 3 hits) is a nav menu ("Research | Blog | Glossary..."). Re-run with 15 s networkidle + 3 s extra buffer produced identical results — timing is not the issue. The `/research` page may be a static index with no repeating post list, or content requires scroll-to-load.

---

### Lumen
- **Confidence:** low
- **Reason:** All 3 candidates (`div.link-container`, `div.card-wrapper`, `div.card.card-default.block`) have CDN image-asset hrefs, not article URLs. Re-run with 15 s networkidle + 3 s buffer produced identical results — timing is not the bottleneck. The blog cards likely embed article links only inside `<picture>` or lazy `data-src` attributes that the heuristic's `querySelector('a')` misses.

---

### txOne
- **Confidence:** low
- **Reason:** All candidates are nav/dropdown elements (`div.min-w-0`, `ul.space-y-3`, `div.max-w-7xl`). Re-run with extended timing produced identical results. Blog listing does not render a repeating post-card grid on this URL — may require infinite-scroll interaction or a different entry URL.

---

### Blackberry
- **Confidence:** low
- **Reason:** Candidates are large container divs (3–5 hits) that wrap entire page sections, not individual post cards. The URL `blogs.blackberry.com/en/home` seems to have redirected to the BlackBerry Secure Communications site, which has a different structure. Can't isolate individual post cards.

---

### Cado Security
- **Status:** moved to `skip`
- **Reason:** Acquired by Darktrace (2024). Content is fully absorbed into `darktrace.com/blog` with no distinct Cado section, tag, or author filter. DarkTrace is already monitored via a separate feed entry (`https://www.darktrace.com/blog/rss.xml`) — this entry is a full duplicate.

---

### eSentire
- **Confidence:** low
- **Reason:** Only candidates are filter-dropdown items (41 hits) and footer nav groups. Re-run with 15 s networkidle + 3 s buffer produced identical results. The post list is an XHR-populated virtual list whose elements are not in the DOM at render time — scroll or pagination trigger required.

---

### Binarly
- **Confidence:** low
- **Reason:** Only 2 candidates, both nav column divs ("Platform | Features | Plans"). Re-run with extended timing produced identical results. The `/learn` page renders no repeating post list — content may be gated, paginated via API, or the page is essentially a landing page with no self-contained post grid.

---

### Cyjax
- **Selector:** `div.resources_list.w-dyn-items div.w-dyn-item` / `link_selector: a`
- **Confidence:** high
- **Reason:** Targeted probe confirmed `div.w-dyn-item` children nested inside the `resources_list` container — 3 siblings, sample link `https://www.cyjax.com/resources/blog/uk-vs-europe-...` is a real blog post. Descendant combinator scopes matches to blog resource items only.

---

### Imperva
- **Selector:** `div.tile-holder.card-div` / `link_selector: a.subtitle-card`
- **Confidence:** high
- **Reason:** Deep anchor probe on 3 cards confirmed the article title anchor carries class `subtitle-card` on every card. The category tag uses class `post-category` (first `a` in the card) — `a.subtitle-card` cleanly skips it. Verified across cards 1–3: all resolve to real `/blog/article-slug/` URLs.

---

### McAfee
- **Confidence:** low
- **Reason:** Page timed out (30 s) during navigation to `https://www.mcafee.com/blogs/other-blogs/`. Likely bot-protected or requires HTTP/2 workaround.

---

### Australian Signals Directorate's Australian Cyber Security Centre (ASD's ACSC)
- **Confidence:** low
- **Reason:** Page timed out (30 s) during navigation to `https://www.cyber.gov.au/about-us/view-all-content/alerts-and-advisories`. May be geo-restricted from this environment.

---

### Phylum
- **Confidence:** low
- **Reason:** Page loaded with no error but 0 candidates both on the initial run and after 15 s networkidle + 3 s buffer. Ghost/custom theme likely uses semantic HTML (`<article>` without shared class names) rather than class-driven post cards, so the class-grouping heuristic finds nothing. Needs manual devtools inspection to locate the repeating element.

---

### Packetstorm
- **Confidence:** low
- **Reason:** Homepage shows section containers (`section.ps-mcard`, `div.ps-col.ps-text`) but all sample links point to category/news-index pages, not individual advisories or exploit entries. The actual file listing is at a different sub-URL (e.g., `/files/`). Consider pointing the URL to a specific news or exploit listing page.

---

### Oligo Security
- **Confidence:** low
- **Reason:** Page loaded with no error but 0 candidates both runs. Re-run with 15 s networkidle + 3 s buffer unchanged. Blog likely uses server-side rendering with no shared class names on post cards, or the post list is behind an API call that doesn't populate DOM elements with discoverable class patterns.

---

### Sectrio
- **Status:** moved to `skip`
- **Reason:** `sectrio.com` 301-redirects to `subex.com`. All sectrio.com subpaths (`/blog/`, `/threat-intelligence/`, individual posts) return HTTP 404. Subex has no distinct Sectrio section. OT/IoT CTI content no longer accessible anywhere.

---

### Truffle Security
- **Confidence:** low
- **Reason:** Framer-rendered blog. Re-run with 15 s networkidle + 3 s buffer returned identical candidates: `p.framer-text` (26 nav items) and `p.framer-text` (6 nav items) — no post-card container. Framer generates per-build opaque class names; the post list's container class does not repeat in the 3–60 range the heuristic requires. Needs manual devtools inspection.

---

### Speartip
- **Selector:** `div.card-content` / `link_selector: a`
- **Confidence:** high
- **Reason:** `speartip.com` redirects to `us.zurichresilience.com`. The `www.` subdomain doesn't render article cards in headless Chromium; `us.` does. Correct URL: `https://us.zurichresilience.com/cybersecurity/articles-and-insights`. `div.card-content` yields 18 hits, sampleHref=`https://www.zurichresilience.com/knowledge-and-insights-hub/articles/2026/05/balancing-progress-and-peril-...` — real article URL. Resolved to `html`.

---

### LastPass
- **Confidence:** low
- **Reason:** Only 2 candidates, both footer nav lists (`ul.footer_footer-section`, `div.footer_footer-column`). Re-run with 15 s networkidle + 3 s buffer produced identical results. The blog listing renders no detectable repeating post cards — likely a paginated API feed or the page structure uses unique class names per post.

---

### Veriti AI
- **Status:** moved to `skip`
- **Reason:** Acquired by Cyberint (Check Point, 2024). `veriti.ai` redirects to `checkpoint.com/exposure-management` (a product page). No Veriti tag, author filter, or sub-blog exists anywhere on `blog.checkpoint.com` or `research.checkpoint.com`. Content fully absorbed with no filterable URL.

---

### F6 Russia
- **Confidence:** low
- **Reason:** Page loaded with no error but 0 candidates both runs. Re-run with extended timing unchanged. The SPA likely renders posts into elements that share no common class prefix, or the content is populated by a locale-specific API call that doesn't settle before the heuristic runs.

---

### Zscaler
- **Confidence:** low
- **Reason:** All 8 candidates are nav/mega-menu elements across both runs (15 s networkidle + 3 s buffer made no difference). The post grid at `?type=security-research` is not populated by a simple timed XHR — it likely requires a user interaction (scroll, tab click, or cookie consent) to render.

---

### StrongestLayer
- **Confidence:** low
- **Reason:** All candidates (`div.item`, `details.macc`, `div.sub`, `div.footer-menu-flex`) are nav/accordion elements across both runs. Re-run with extended timing produced identical results. The `/research` page appears to contain no repeating post-card grid — possibly a single-post landing page or all content is in a non-repeating layout.

---

### Interlab
- **Confidence:** low
- **Reason:** Page timed out during navigation to `https://interlab.or.kr/`. Site may be down or geo-restricted.

---

### Kroll
- **Selector:** `div.md\:col-span-4` / `link_selector: a`
- **Confidence:** high
- **Reason:** URL corrected from homepage to `https://www.kroll.com/en/insights/cyber` (Kroll Cyber and Data Resilience Blog). 20 hits; sampleHref=real cyber article. **Note:** class name contains a Tailwind colon (`md:col-span-4`) which must be escaped as `md\:col-span-4` in CSS selectors — the unescaped form raises a `SyntaxError` in Playwright's `querySelectorAll`. Config JSON stores `"div.md\\:col-span-4"` (double backslash). Confirmed 20/20 on run_check.py after fix. Resolved to `html`.

---

### Secureworks
- **Confidence:** low
- **Reason:** Page timed out during navigation. This is a known HTTP/2 issue (noted in `recheck_playwright.py` comments). Try with `--disable-http2` flag or a longer timeout.

---

### Trellix (research blog)
- **Confidence:** low
- **Reason:** Page timed out during navigation to `https://www.trellix.com/blogs/research/`. HTTP/2 protocol error — same issue documented in `recheck_playwright.py`.

---

### Trellix (main blogs)
- **Confidence:** low
- **Reason:** Page timed out during navigation to `https://www.trellix.com/blogs/`. Same HTTP/2 issue as research blog.

---

### Sophos
- **Confidence:** low
- **Reason:** Page timed out during navigation to `https://news.sophos.com/en-us/`. HTTP/2 issue — listed alongside McAfee, Trellix, and Secureworks in `recheck_playwright.py` as known problem sites. May work with `--disable-http2` on a slower page load.

---

## SKIPPED — HTTP/2 confirmed unfixable (2026-07-29)

These sites timed out in headless Chromium due to HTTP/2 protocol errors. Tried twice with `--disable-http2` flag and extended timeout (15 s networkidle + 3 s buffer). Issue is structural — not a timing problem. Moved to `skip`; requires manual monitoring.

### McAfee
- **Confidence:** n/a (skip)
- **Reason:** HTTP/2 protocol error. Two attempts with `--disable-http2` and extended timeout both failed. `https://www.mcafee.com/blogs/other-blogs/`

### Secureworks
- **Confidence:** n/a (skip)
- **Reason:** HTTP/2 protocol error. Two attempts with `--disable-http2` and extended timeout both failed. `https://www.secureworks.com/blog/`

### Trellix (research blog)
- **Confidence:** n/a (skip)
- **Reason:** HTTP/2 protocol error. Two attempts with `--disable-http2` and extended timeout both failed. `https://www.trellix.com/blogs/research/`

### Trellix (main blogs)
- **Confidence:** n/a (skip)
- **Reason:** HTTP/2 protocol error. Two attempts with `--disable-http2` and extended timeout both failed. `https://www.trellix.com/blogs/`

### Sophos
- **Confidence:** n/a (skip)
- **Reason:** HTTP/2 protocol error. Two attempts with `--disable-http2` and extended timeout both failed. `https://news.sophos.com/en-us/`

---

## Summary

| Outcome | Count |
|---|---|
| Resolved to `html` (high confidence) | 25 |
| Resolved to `html` (medium confidence) | 2 |
| Moved to `skip` (content gone or duplicate) | 11 |
| Moved to `skip` (HTTP/2 — confirmed unfixable) | 5 |
| Remain `html_TODO` — needs manual inspection | 16 |

**html_TODO sites still needing a human:**
- **ASD's ACSC, Interlab** — navigation timed out; site may be geo-restricted or down
- **Blackberry** — redirected to Secure Communications site; post cards not isolable from heuristic
- **Packetstorm** — homepage structure doesn't expose individual article URLs; needs a specific listing sub-URL
- **GetSafety, Lumen, txOne, eSentire, Binarly, Phylum, Oligo Security, Truffle Security, LastPass, F6 Russia, Zscaler, StrongestLayer** — timing confirmed not the issue; need scroll interaction, different entry URL, or manual devtools inspection
