# opsclaw.io — the static site

The second frontend from DESIGN.md §7.11: marketing + docs + downloads for
opsclaw.io, **purely static, zero coupling to any daemon**. The operational
web UI is the other frontend — embedded in the daemon binary, one per team,
internal-only; nothing here reaches into any deployment and no hosted
console exists on purpose.

No build step, no framework, no external assets (fonts, CDNs, analytics):
one hand-written page, self-contained CSS. Deploy by pointing any static
host (Cloudflare Pages, Netlify, an nginx root) at this directory.

Content discipline: everything stated on the page must be true of the
shipped binary — the page describes the policy gate, audit chain, and
autonomy levels exactly as `docs/DESIGN.md` defines them. Update the two
together or not at all.
