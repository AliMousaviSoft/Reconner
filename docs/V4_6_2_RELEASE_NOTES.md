# Reconner v4.6.2 — Project detail page: tabs and descriptions match the project type

The project detail page (`/targets/:id`) used to show the exact same generic
tab set — Hosts, URLs, Scripts, Parameters, Directories, Admin panels,
Confirmed, Needs Review, Open Redirects, Nuclei, JS/Secrets, Exposed Files,
Changes — for every project, regardless of whether it was a web, network or
WordPress scan. A network (IP/CIDR) project never populates most of those
(nothing in the network pipeline writes to the subdomain/JS/parameter/
directory/admin-panel/open-redirect tables), and a WordPress project's own
plugin/theme/user/endpoint inventory was buried inside the generic Confirmed/
Needs Review lists, indistinguishable from an actual XSS or SQLi finding.

## Tabs now adapt to the project's type

- **Network projects** show only what the network pipeline actually
  produces: Network services, Confirmed, Needs Review, Nuclei, Changes. The
  web-crawl-only tabs are gone — there was never anything in them for an
  IP/CIDR scope.
- **WordPress projects** (created from the WP Scanner, or any project tagged
  `wp-scanner`) get a new **WordPress** tab group:
  - **Plugins & Themes** — core version, plugins and themes, each confirmed
    from the site's own assets/readme (wp_enum).
  - **Users** — usernames WordPress itself discloses via the REST users
    route, author-archive redirect or oembed (wp_users).
  - **Endpoints** — login page, REST API root, admin-ajax and XML-RPC
    (wp_endpoints).

  These are confirmed recon *facts* about the install, not vulnerability
  candidates, so they're pulled out of Confirmed/Needs Review into their own
  clearly-labeled place. Needs Review and Confirmed on a WordPress project
  now show only genuine vulnerabilities (config/backup exposure, open
  misconfiguration, XML-RPC amplification, weak credentials, …) — no more
  "plugin X is present" sitting next to a real XSS candidate.
- **Web projects** are unchanged — same tab set as before.

Every tab now also carries a one-line description, shown as a tooltip on the
tab itself and as a caption under the tab bar for whichever tab is open, so
the UI explains what each tab actually shows instead of a bare label.

## No backend changes

This is a frontend-only release: the WordPress inventory/endpoint data was
always recorded through the normal finding pipeline (`vuln_findings`) with
type prefixes like `wordpress_plugin`/`wordpress_user_enumeration`/
`wordpress_login_panel` — the detail page now filters and groups the same
data by type instead of treating every row identically.

## Upgrade

No migration, no new dependencies. Rebuild/redeploy the frontend.
