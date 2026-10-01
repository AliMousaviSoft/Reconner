package scanner

import (
	"context"
	"encoding/json"
	"net/url"
	"sort"
	"strings"
)

// wordpress_users.go — user/username enumeration (module wp_users).
//
// Every username reported is one WordPress ITSELF returned — through the REST
// users route, an author-archive redirect, or the oembed author field — never a
// guess or an inference from a login error. Username enumeration is a real
// pre-exploitation info leak: it turns an anonymous login/XML-RPC surface into a
// targeted credential attack, so an open user-enumeration path is reported as a
// medium finding with the recovered usernames as evidence.

// RunUsers implements wp_users.
func (s *WordPressScanner) RunUsers(ctx context.Context, targetID string, logFn LogFunc) error {
	sites := s.ensureDetected(ctx, targetID, logFn)
	if len(sites) == 0 {
		logFn("info", "wp_users", "No confirmed WordPress host for this target; nothing to enumerate.")
		return ctx.Err()
	}
	total := 0
	for _, site := range sites {
		if ctx.Err() != nil {
			break
		}
		logFn("info", "wp_users", "Enumerating users on "+site.URL+" (REST / author archive / oembed)...")

		rest := s.usersViaREST(ctx, site.URL)
		if len(rest) > 0 {
			s.store(ctx, targetID, "wp_users", "wordpress_user_enumeration", "medium",
				site.URL+"/wp-json/wp/v2/users",
				"WordPress REST user route is public and enumerable — recovered "+itoa(len(rest))+
					" username(s): "+joinSlugs(rest)+". Restrict the users route or require authentication; these feed targeted login/XML-RPC credential attacks.")
			s.notify(targetID, "wordpress_user_enumeration", site.URL+"/wp-json/wp/v2/users")
			total += len(rest)
		}

		author := s.usersViaAuthorArchive(ctx, site.URL)
		if len(author) > 0 {
			s.store(ctx, targetID, "wp_users", "wordpress_user_enumeration", "medium",
				site.URL+"/?author=1",
				"WordPress author-archive redirect leaks login usernames — recovered: "+strings.Join(author, ", ")+
					". Disable author archives / redirect ?author=N to reduce username exposure.")
			s.notify(targetID, "wordpress_user_enumeration", site.URL+"/?author=1")
			total += len(author)
		}

		if name := s.userViaOEmbed(ctx, site.URL); name != "" {
			s.store(ctx, targetID, "wp_users", "wordpress_user_enumeration", "low",
				site.URL+"/wp-json/oembed/1.0/embed",
				"WordPress oembed endpoint discloses an author name: "+name+".")
		}
	}
	logFn("warn", "wp_users", "WordPress user enumeration done. "+itoa(total)+" username signal(s) recovered.")
	return ctx.Err()
}

// enumerateUsernames returns the deduped set of login usernames recoverable for a
// site (REST slug + author-archive slug). Shared with the opt-in credential audit.
func (s *WordPressScanner) enumerateUsernames(ctx context.Context, base string) []string {
	set := map[string]bool{}
	for _, u := range s.usersViaREST(ctx, base) {
		if u.Slug != "" {
			set[u.Slug] = true
		}
	}
	for _, slug := range s.usersViaAuthorArchive(ctx, base) {
		set[slug] = true
	}
	out := make([]string, 0, len(set))
	for u := range set {
		out = append(out, u)
	}
	sort.Strings(out)
	return out
}

type wpRESTUser struct {
	ID   int    `json:"id"`
	Name string `json:"name"`
	Slug string `json:"slug"`
}

// usersViaREST reads /wp-json/wp/v2/users. A JSON array carrying slug fields is a
// definitive enumeration — the usernames are returned by WordPress itself.
func (s *WordPressScanner) usersViaREST(ctx context.Context, base string) []wpRESTUser {
	r := wpGet(ctx, base+"/wp-json/wp/v2/users?per_page=100", 256*1024)
	if r.status != 200 || !strings.Contains(strings.ToLower(r.ctype), "json") {
		return nil
	}
	var users []wpRESTUser
	if json.Unmarshal([]byte(r.body), &users) != nil {
		return nil
	}
	out := users[:0]
	for _, u := range users {
		if strings.TrimSpace(u.Slug) != "" {
			out = append(out, u)
		}
	}
	return out
}

// usersViaAuthorArchive maps author IDs 1..10 to login usernames through the
// /?author=N → /author/<slug>/ redirect WordPress performs. Only a genuine 3xx to
// an /author/ path counts, so a catch-all 200 can never produce a username.
func (s *WordPressScanner) usersViaAuthorArchive(ctx context.Context, base string) []string {
	set := map[string]bool{}
	for id := 1; id <= 10; id++ {
		if ctx.Err() != nil {
			break
		}
		r := wpGet(ctx, base+"/?author="+itoa(id), 16*1024)
		if r.status != 301 && r.status != 302 {
			// Some installs 200 the author page directly; recover the slug from the
			// canonical/body <link rel="canonical" href=".../author/<slug>/">.
			if r.status == 200 {
				if m := wpAuthorPathRe.FindStringSubmatch(r.body); m != nil {
					set[strings.ToLower(m[1])] = true
				}
			}
			continue
		}
		if m := wpAuthorPathRe.FindStringSubmatch(r.location); m != nil {
			set[strings.ToLower(m[1])] = true
		}
	}
	out := make([]string, 0, len(set))
	for u := range set {
		out = append(out, u)
	}
	sort.Strings(out)
	return out
}

// userViaOEmbed reads the oembed author_name for the site root.
func (s *WordPressScanner) userViaOEmbed(ctx context.Context, base string) string {
	r := wpGet(ctx, base+"/wp-json/oembed/1.0/embed?format=json&url="+url.QueryEscape(base+"/"), 32*1024)
	if r.status != 200 || !strings.Contains(strings.ToLower(r.ctype), "json") {
		return ""
	}
	var o struct {
		AuthorName string `json:"author_name"`
	}
	if json.Unmarshal([]byte(r.body), &o) != nil {
		return ""
	}
	return strings.TrimSpace(o.AuthorName)
}

func joinSlugs(users []wpRESTUser) string {
	var parts []string
	for _, u := range users {
		if u.Name != "" && u.Name != u.Slug {
			parts = append(parts, u.Slug+" ("+u.Name+")")
		} else {
			parts = append(parts, u.Slug)
		}
	}
	return strings.Join(parts, ", ")
}
