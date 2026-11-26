// SPDX-License-Identifier: AGPL-3.0-only

// Package panel is the operator console's BROWSER surface (myne-md/myne#787): a
// read-only web page rendering the same live enforcement state as the admin API,
// gated by MYNE_ADMIN_PANEL_ADDR and served by myne-server itself.
//
// Read-only is structural, not a convention. This package depends on
// internal/console for its data and on nothing else from the server, and
// internal/console contains no write path, so there is no expression here that can
// name one. The route table registers GET (and therefore HEAD) only, so the standard
// library answers 405 for every other method on every path. "Somebody added a
// destructive button by mistake" is not a state this code can be in.
//
// What it deliberately does NOT do, and why:
//
//   - No request log. The panel is the first operator surface an operator can put
//     on a network, and self-host-policy §3 prohibits IP logging anywhere in an
//     operator's stack, so anything logged here would make a deployment violate its
//     own contract. internal/httpapi adds no access-log middleware to it.
//   - No chart with a time axis, no sampling, no persisted state. It is an
//     instantaneous projection of what the server already holds, which is what
//     keeps it from being a new observation channel (MYND-440).
//   - No time value of any kind in the output. The server stores no user-meaningful
//     timestamp, so a "read at" line would be exactly the wall-clock the aggregate-
//     only invariant forbids.
//   - No account number. There is none to render: the raw number never crosses the
//     sync wire and a raw-form username is refused at registration, so the hash is
//     the only identifier this surface has.
package panel

import (
	"embed"
	"fmt"
	"html/template"
	"net"
	"net/http"
	"strings"

	"github.com/myne-md/myne-server/internal/console"
)

//go:embed panel.html panel.css
var assets embed.FS

// page is the single view. It is parsed once at init; a template error here is a
// programming error, not a runtime condition.
//
// The template name MUST be the asset's base name: ParseFS names each parsed file
// after its base, so naming it anything else yields a template that parses fine and
// then executes as empty. That renders a blank page with a 200 and no error, which
// is exactly the kind of green that means nothing.
var page = template.Must(template.New("panel.html").Funcs(template.FuncMap{
	"humanBytes": humanBytes,
	"abbrevHash": abbrevHash,
	"limit":      limitLabel,
}).ParseFS(assets, "panel.html"))

type Panel struct {
	proj *console.Projection
	// allowHosts is the set of Host header values the panel answers to. See New for
	// why this exists and why it has to be an allowlist.
	allowHosts map[string]bool
}

// New builds the panel over the shared read projection.
//
// allowedHosts is a comma-separated list of Host values the panel will answer to.
// EMPTY MEANS LOOPBACK NAMES ONLY.
//
// This is the DNS-rebinding defence, and it cannot be anything else. The panel is
// unauthenticated and serves the account roster, so a hostile page the operator
// visits must not be able to read it. The two usual answers do not hold here:
//
//   - The same-origin policy does not help: a rebound name (attacker.test
//     re-resolving to 127.0.0.1) is SAME-ORIGIN to the attacker's own page, so the
//     browser hands it the response.
//   - An Origin check does not help: browsers OMIT Origin on a GET, so the very
//     header that would catch a rebound fetch is not sent. Sec-Fetch-Site is no
//     better, because a same-origin request reports same-origin, which a rebound
//     request is.
//
// Validating Host against a known set is the only check that survives both. The cost
// is that an operator who binds a LAN address must name the host they will browse
// to, which is stated here rather than left for someone to discover as a 403.
func New(proj *console.Projection, allowedHosts string) *Panel {
	p := &Panel{proj: proj, allowHosts: map[string]bool{}}
	for _, h := range strings.Split(allowedHosts, ",") {
		if h = strings.TrimSpace(h); h != "" {
			p.allowHosts[strings.ToLower(h)] = true
		}
	}
	return p
}

// hostAllowed reports whether a Host header value may be served. The port is dropped
// before comparison so an allowlist entry of "127.0.0.1" covers "127.0.0.1:8099".
func (p *Panel) hostAllowed(host string) bool {
	host = strings.ToLower(host)
	if host == "" {
		return false
	}
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	if host == "localhost" {
		return true
	}
	if ip := net.ParseIP(host); ip != nil && ip.IsLoopback() {
		return true
	}
	return p.allowHosts[host]
}

// Mux returns the panel's HTTP handler. It registers two GET routes (the page and
// its stylesheet) and nothing else, so every other path 404s and every other method
// 405s on both. The Host check wraps both, so a rebound name is refused before any
// roster is rendered.
func (p *Panel) Mux() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /{$}", p.handleIndex)
	mux.HandleFunc("GET /panel.css", serveCSS)
	return p.requireAllowedHost(mux)
}

func (p *Panel) requireAllowedHost(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !p.hostAllowed(r.Host) {
			// Deliberately terse. Naming the allowed hosts here would turn a probe
			// into a discovery oracle, and this is a refusal rather than a
			// tutorial; the operator's own config is the thing to read.
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			w.WriteHeader(http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// serveCSS serves the embedded stylesheet. It reads the one named file out of the
// embedded FS rather than handing http.FileServer the directory, so the asset
// surface is exactly this file and cannot grow a listing or a traversal by accident.
func serveCSS(w http.ResponseWriter, _ *http.Request) {
	body, err := assets.ReadFile("panel.css")
	if err != nil {
		// Unreachable: the file is embedded at compile time or the build fails.
		http.Error(w, "stylesheet unavailable", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/css; charset=utf-8")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write(body)
}

type row struct {
	Hash        string
	FullHash    string
	Bytes       uint64
	Devices     uint64
	Frozen      bool
	QuotaSet    bool
	MaxDevsSet  bool
	DevicesText string
}

type pageData struct {
	Accounts      uint64
	StoredBytes   uint64
	Frozen        uint64
	MaxAccounts   string
	HasAccounts   bool
	HasFrozen     bool
	Rows          []row
	BackendIsMem  bool
	BytesHuman    string
	UnlimitedText string
}

func (p *Panel) handleIndex(w http.ResponseWriter, _ *http.Request) {
	// ONE enumeration, not two. Stats() calls Accounts() internally, so asking for
	// both walked the whole store twice per page load, and each pass issues a
	// per-account usedBytes + device count + policy read. On a large deployment that
	// is a measurable cost on an unauthenticated listener, and it is a timing channel
	// over the roster on top.
	views := p.proj.Accounts()
	stats := console.StatsOf(views, p.proj.MaxAccounts())

	rows := make([]row, 0, len(views))
	for _, v := range views {
		rows = append(rows, row{
			Hash:        abbrevHash(v.AccountHash),
			FullHash:    v.AccountHash,
			Bytes:       v.StoredBytes,
			Devices:     v.DeviceCount,
			Frozen:      v.Frozen,
			QuotaSet:    v.QuotaOverrideBytes != 0,
			MaxDevsSet:  v.MaxDevicesOverride != 0,
			DevicesText: limitLabel(v.MaxDevicesOverride),
		})
	}

	data := pageData{
		Accounts:      stats.TotalAccounts,
		StoredBytes:   stats.TotalStoredBytes,
		Frozen:        stats.FrozenAccounts,
		MaxAccounts:   limitLabel(stats.MaxAccounts),
		HasAccounts:   stats.TotalAccounts > 0,
		HasFrozen:     stats.FrozenAccounts > 0,
		Rows:          rows,
		BytesHuman:    humanBytes(stats.TotalStoredBytes),
		UnlimitedText: "unlimited",
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Referrer-Policy", "no-referrer")
	// The account roster must not survive in a browser or proxy cache. The
	// stylesheet already said no-store; the page carrying the data did not.
	w.Header().Set("Cache-Control", "no-store")
	// A read-only page with no scripts of its own and no third-party anything. The
	// only inline script is the copy button's, and it touches no network.
	w.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'self'; script-src 'unsafe-inline'; form-action 'none'; base-uri 'none'; frame-ancestors 'none'")
	if err := page.Execute(w, data); err != nil {
		// A template failure after the header is written cannot be turned into a
		// status code. There is nothing to recover, and nothing here is worth a
		// panic that would print a stack.
		return
	}
}

// abbrevHash shortens a 64-char hex hash for a table cell without hiding it: the
// first six and last four characters, with the full value one click away. This is
// readability, NOT redaction: the value is not a secret (it is a non-reversible
// pseudonym) and it is served in full in the row's copy payload.
func abbrevHash(h string) string {
	if len(h) <= 12 {
		return h
	}
	return h[:6] + "…" + h[len(h)-4:]
}

// limitLabel renders a ceiling, where 0 means UNLIMITED and never a ceiling of
// zero (server-protocol §7.1). An operator on a deployment with no ceilings set
// must not be shown a limit language or a ratio against nothing.
func limitLabel(v uint64) string {
	if v == 0 {
		return "unlimited"
	}
	return fmt.Sprintf("%d", v)
}

func humanBytes(n uint64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := uint64(unit), 0
	for m := n / unit; m >= unit; m /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", float64(n)/float64(div), "KMGTPE"[exp])
}
