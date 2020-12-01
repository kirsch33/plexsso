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

type OmbiToken struct {
	TokenValue string `json:"access_token,omitempty"`
	Expiration string `json:"expiration,omitempty"`
}

type PlexToken struct {
	TokenValue string `json:"plexToken,omitempty"`
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
	
	ref := req.Header.Get("Referer")
	host := req.Host
	cookie, err := req.Cookie("Auth")
	
	if ref=="https://greatwhitelab.net/auth/portal" && host=="ombi.greatwhitelab.net" && err != nil {
		
		var plexToken = PlexToken {
			TokenValue: s.TokenValue,
		}
		
		req_body, err := json.Marshal(&plexToken)

		//s.logger.Debug("kodiak request_body", zap.String("req_body",string(req_body)))
		
		if err != nil {
			return fmt.Errorf("Request token formatting error: %s", err)
		}
		
		FullOmbiHostPath := s.OmbiHost + "/api/v1/token/plextoken"
		
		request, err := http.NewRequest("POST", FullOmbiHostPath, bytes.NewBuffer(req_body))
		//resp, err := http.Post(FullOmbiHostPath, "application/json", bytes.NewBuffer(req_body))
		//s.logger.Debug("kodiak ombifullpath", zap.String("FullOmbiHostPath",string(FullOmbiHostPath)))
		
		if err != nil {
			return fmt.Errorf("Request error: %s", err)
		}
		
		request.Header.Set("Content-Type", "application/json")
		request.Header.Set("Accept", "application/json")
		
		client := &http.Client{}
    		response, err := client.Do(request)

		if err != nil {
			return fmt.Errorf("Response error: %s", err)
		}
		
		body, err := ioutil.ReadAll(response.Body)
		
		if err != nil {
			return fmt.Errorf("Response token formatting error: %s", err)
		}
		
		//s.logger.Debug("kodiak body", zap.String("body",string(body)))
		
		var ombiToken OmbiToken
		err = json.Unmarshal(body, &ombiToken)
		
		if err != nil {
			return fmt.Errorf("Response unmarshal error: %s", err)
		}
		
		//s.logger.Debug("kodiak ombi toke value", zap.String("ombi token value",ombiToken.TokenValue))
		
		authCookie := http.Cookie {
			Name:		"Auth",
			Value:		ombiToken.TokenValue,
			Domain:		"greatwhitelab.net",
			HttpOnly:	false,
			SameSite:	http.SameSiteLaxMode,
			Path:		"/",
			Secure:		true,
			Expires:	time.Now().Add(24*time.Hour),
		}
		
		w.Header().Set("Location", "https://ombi.greatwhitelab.net/auth/cookie")
		
		//s.logger.Debug("kodiak location", zap.String("location header",req.Host+"/auth/cookie"))
		w.Header().Set("Set-Cookie", authCookie.String())
		//s.logger.Debug("kodiak set cookie", zap.String("set-cookie",string(authCookie.String())))
		w.WriteHeader(http.StatusFound)
		defer response.Body.Close()
		
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
