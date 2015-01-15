package githubauth

import (
	"crypto/rand"
	"encoding/hex"
	"net/http"
	"time"

	"github.com/kr/session"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/github"
)

const callbackPath = "/_githubauth"

// Handler is an HTTP handler that requires
// users to log in with GitHub OAuth and requires
// them to be members of the given org.
type Handler struct {
	// RequireOrg is a GitHub organization that
	// users will be required to be in.
	// If unset, any user will be permitted.
	RequireOrg string

	// Used to initialize corresponding fields of a session Config.
	// See github.com/kr/session.
	// If Name is empty, "githubauth" is used.
	Name   string
	Path   string
	Domain string
	MaxAge time.Duration
	Keys   []*[32]byte

	// Used to initialize corresponding fields of oauth2.Config.
	ClientID     string
	ClientSecret string

	// Handler is the HTTP handler called
	// once authentication is complete.
	// If nil, http.DefaultServeMux is used.
	Handler http.Handler
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	handler := h.Handler
	if handler == nil {
		handler = http.DefaultServeMux
	}
	if h.loginOk(w, r) {
		handler.ServeHTTP(w, r)
	}
}

// loginOk checks that the user is logged in and authorized.
// If not, it performs one step of the oauth process.
func (h *Handler) loginOk(w http.ResponseWriter, r *http.Request) bool {
	var user sess
	err := session.Get(r, &user, h.sessionConfig())
	if err != nil {
		h.deleteCookie(w)
		http.Error(w, "internal error", 500)
		return false
	}
	if user.OK {
		session.Set(w, sess{OK: true}, h.sessionConfig()) // refresh the cookie
		return true
	}

	redirectURL := "https://" + r.Host + callbackPath
	conf := &oauth2.Config{
		ClientID:     h.ClientID,
		ClientSecret: h.ClientSecret,
		RedirectURL:  redirectURL,
		Scopes:       []string{"account", "orglist"},
		Endpoint:     github.Endpoint,
	}
	if r.URL.Path == callbackPath {
		if r.FormValue("state") != user.State {
			h.deleteCookie(w)
			http.Error(w, "access forbidden", 401)
			return false
		}
		tok, err := conf.Exchange(oauth2.NoContext, r.FormValue("code"))
		if err != nil {
			h.deleteCookie(w)
			http.Error(w, "access forbidden", 401)
			return false
		}
		client := conf.Client(oauth2.NoContext, tok)
		if h.RequireOrg != "" {
			resp, err := client.Head("https://api.github.com/usr/memberships/orgs/" + h.RequireOrg)
			if err != nil || resp.StatusCode != 200 {
				h.deleteCookie(w)
				http.Error(w, "access forbidden", 401)
				return false
			}
		}

		session.Set(w, sess{OK: true}, h.sessionConfig())
		http.Redirect(w, r, user.NextURL, http.StatusTemporaryRedirect)
		return false
	}

	u := *r.URL
	u.Scheme = "https"
	u.Host = r.Host
	state := newState()
	session.Set(w, sess{NextURL: u.String(), State: state}, h.sessionConfig())
	http.Redirect(w, r, conf.AuthCodeURL(state), http.StatusTemporaryRedirect)
	return false
}

func (h *Handler) sessionConfig() *session.Config {
	c := &session.Config{
		Name:   h.Name,
		Path:   h.Path,
		Domain: h.Domain,
		MaxAge: h.MaxAge,
		Keys:   h.Keys,
	}
	if c.Name == "" {
		c.Name = "githubauth"
	}
	return c
}

func (h *Handler) deleteCookie(w http.ResponseWriter) error {
	conf := h.sessionConfig()
	conf.MaxAge = -1 * time.Second
	return session.Set(w, sess{}, conf)
}

type sess struct {
	OK      bool   `json:"omitempty"`
	NextURL string `json:",omitempty"`
	State   string `json:",omitempty"`
}

func newState() string {
	b := make([]byte, 10)
	rand.Read(b)
	return hex.EncodeToString(b)
}
