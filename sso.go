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

type plexsso struct {
	TokenValue string
	OmbiHost string
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
	
	h := req.Header.Get("Referer")

	if h=="https://greatwhitelab.net/auth/portal" {
		
		req_body, err := json.Marshal(map[string]string{"plexToken":s.TokenValue})

		s.logger.Debug("kodiak request_body", zap.String("req_body",string(req_body)))
		
		if err != nil {
			return fmt.Errorf("Token formatting error: %s", err)
		}
		
		FullOmbiHostPath := s.OmbiHost + "/api/v1/token/plextoken"
		resp, err := http.Post(FullOmbiHostPath, "application/json", bytes.NewBuffer(req_body))
		
		if err != nil {
			return fmt.Errorf("Response error: %s", err)
		}

		res_body, err := ioutil.ReadAll(resp.Body)
		
		if err != nil {
			return fmt.Errorf("Response body read error: %s", err)
		}
		
		authCookie := http.Cookie {
			Name:		"Auth",
			Value:		res_body,
			Domain:		"ombi.greatwhitelab.net",
			HttpOnly:	false,
			SameSite:	http.SameSiteLaxMode,
			Path:		"/",
			Secure:		false,
			Expires:	time.Now().Add(24*time.Hour),
		}
		
		req.AddCookie(&authCookie)
		
		defer resp.Body.Close()
		return handler.ServeHTTP(w, req) 
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
				case "token":
					args := d.RemainingArgs()
					s.TokenValue = args[0]		
				case "host":
					args := d.RemainingArgs()
					s.OmbiHost = args[0]	
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
