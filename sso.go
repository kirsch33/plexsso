package plexsso

import (
	"fmt"
	"net/http"
	"bytes"
	"encoding/json"
	"io/ioutil"
	"time"
	
	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"go.uber.org/zap"
)

type User struct {
	Name string
	TokenValue string
}

type OmbiToken struct {
	TokenValue string `json:"access_token,omitempty"`
	Expiration string `json:"expiration,omitempty"`
}

type PlexToken struct {
	TokenValue string `json:"plexToken,omitempty"`
}

type plexsso struct {
	UserEntry []*User
	OmbiHost string
	Referer string
	logger *zap.Logger
}

func init() {
	caddy.RegisterModule(plexsso{})
	httpcaddyfile.RegisterHandlerDirective("plexsso", parseCaddyfileHandler)
}

func (s *plexsso) Provision(ctx caddy.Context) error {
	s.logger = ctx.Logger(s) 

	return nil
}

func (plexsso) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID: "http.handlers.plexsso",
		New: func() caddy.Module {
			return new(plexsso)
		},
	}
}

func parseCaddyfileHandler(h httpcaddyfile.Helper) (caddyhttp.MiddlewareHandler, error) {
	var s plexsso
	err := s.UnmarshalCaddyfile(h.Dispenser)

	return s, err
}

func (s plexsso) ServeHTTP(w http.ResponseWriter, req *http.Request, handler caddyhttp.Handler) error {
	
	//s.logger.Debug("kodiak request_body", zap.String("req_body",string(req_body)))
	referer := req.Header.Get("Referer")
	subject := req.Header.Get("X-Token-Subject")
	host := req.Host
	_, err := req.Cookie("Auth")
	
	if referer==s.Referer && host==s.OmbiHost && err != nil {
		for _, x := range s.UserEntry {
			if x.Name == subject {
		
				var plex_token = PlexToken {
					TokenValue: x.TokenValue,
				}

				request_body, err := json.Marshal(&plex_token)

				if err != nil {
					return fmt.Errorf("Request token formatting error: %s", err)
				}

				request_url := "https://" + host + "/api/v1/token/plextoken"

				request, err := http.NewRequest("POST", request_url, bytes.NewBuffer(request_body))

				if err != nil {
					return fmt.Errorf("Request error: %s", err)
				}

				req_cookies := req.Cookies()

				for i := range req_cookies {
					request.AddCookie(req_cookies[i])
				}

				request.Header.Set("Content-Type", "application/json")
				request.Header.Set("Accept", "application/json")

				client := &http.Client{}
				response, err := client.Do(request)

				if err != nil {
					return fmt.Errorf("Response error: %s", err)
				}

				response_body, err := ioutil.ReadAll(response.Body)

				if err != nil {
					return fmt.Errorf("Response body read error: %s", err)
				}

				var ombi_token OmbiToken
				err = json.Unmarshal(response_body, &ombi_token)

				if err != nil {
					return fmt.Errorf("Response body unmarshal error: %s", err)
				}

				auth_cookie := http.Cookie {
					Name:		"Auth",
					Value:		ombi_token.TokenValue,
					Domain:		"greatwhitelab.net",
					HttpOnly:	false,
					SameSite:	http.SameSiteLaxMode,
					Path:		"/",
					Secure:		true,
					Expires:	time.Now().Add(24*time.Hour),
				}

				w.Header().Set("Location", string("https://" + host + "/auth/cookie"))
				w.Header().Set("Set-Cookie", auth_cookie.String())
				w.WriteHeader(http.StatusFound)
				defer response.Body.Close()

				return handler.ServeHTTP(w, req) 
			}
		}
	}
	
	return handler.ServeHTTP(w, req)
}
	
func (s *plexsso) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	
	for d.Next() {	
		args := d.RemainingArgs()
		if len(args) > 0 {
			return d.Errf("plexsso supports only nested args: %v", args)
		}
		
		for nesting := d.Nesting(); d.NextBlock(nesting); {
			rootDirective := d.Val()
			switch rootDirective {
				case "user":
					args := d.RemainingArgs()
					s.UserEntry = append(s.UserEntry, args[0], args[1])	
				case "host":
					args := d.RemainingArgs()
					s.OmbiHost = args[0]	
				case "referer":
					args := d.RemainingArgs()
					s.Referer = args[0]
				default:
					return d.Errf("Unknown plexsso arg")
			}
		}
	}
	return nil
}

var (
	_ caddy.Provisioner           = (*plexsso)(nil)
	_ caddyhttp.MiddlewareHandler = (*plexsso)(nil)
	_ caddyfile.Unmarshaler       = (*plexsso)(nil)
)
