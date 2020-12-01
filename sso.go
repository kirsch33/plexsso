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
	_, err := req.Cookie("Auth")
	
	if ref=="https://greatwhitelab.net/auth/portal" && host=="ombi.greatwhitelab.net" && err != nil {
		
		var plexToken = PlexToken {
			TokenValue: s.TokenValue,
		}
		
		request_body, err := json.Marshal(&plexToken)

		//s.logger.Debug("kodiak request_body", zap.String("req_body",string(req_body)))
		
		if err != nil {
			return fmt.Errorf("Request token formatting error: %s", err)
		}
		
		FullOmbiHostPath := "https://" + host + "/api/v1/token/plextoken"
		
		request, err := http.NewRequest("POST", FullOmbiHostPath, bytes.NewBuffer(request_body))

		if err != nil {
			return fmt.Errorf("Request error: %s", err)
		}
		
		req_cookies := req.Cookies()
		
		for i := range req_cookies {
			request.AddCookie(req_cookies[i])
		}
		
		request.Header.Set("Content-Type", "application/json")
		request.Header.Set("Accept", "application/json")
   		
		if err != nil {
        		return fmt.Errorf("Request URL error: %s", err)
    		}   
		
		client := &http.Client{}
    		response, err := client.Do(request)

		if err != nil {
			return fmt.Errorf("Response error: %s", err)
		}
		
		body, err := ioutil.ReadAll(response.Body)
		
		if err != nil {
			return fmt.Errorf("Response token formatting error: %s", err)
		}
		
		var ombiToken OmbiToken
		err = json.Unmarshal(body, &ombiToken)
		
		if err != nil {
			return fmt.Errorf("Response unmarshal error: %s", err)
		}
		
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
		w.Header().Set("Set-Cookie", authCookie.String())
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
