package plexsso

import (
	//"fmt"
	"net/http"
	"bytes"
	"encoding/json"
	"io/ioutil"
	//"strconv"
	//"os"
	
	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"go.uber.org/zap"
	//"go.uber.org/zap/zapcore"
)

type plexsso struct {
	plex_token string
	logger *zap.Logger
}

type token struct {
	plexToken string
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
	if err != nil {
		return nil, err
	}
	return s, err
}

func parseStringArg(d *caddyfile.Dispenser, out *string) error {
	if !d.Args(out) {
		return d.ArgErr()
	}
	return nil
}

func (s plexsso) ServeHTTP(w http.ResponseWriter, req *http.Request, handler caddyhttp.Handler) error {
	
	//u := req.URL.String()
	h := req.Header.Get("Referer")
	
	//s.logger.Debug("kodiak u", zap.String("u",string(u)))
	//s.logger.Debug("kodiak h", zap.String("h",string(h)))
	
	//if u=="https://ombi.greatwhitelab.net/" && h=="https://greatwhitelab.net/auth/portal" {
	if h=="https://greatwhitelab.net/auth/portal" {
		t := token{s.plex_token}
		req_body, err := json.Marshal(t)
		
		s.logger.Debug("kodiak plex_token", zap.String("plex_token",string(s.plex_token)))
		s.logger.Debug("kodiak request_body", zap.String("req_body",string(req_body)))
		
		if err != nil {
			return fmt.Errorf("Token formatting error: %s", err)
		}
		
		resp, err := http.Post("http://192.168.42.12:3579/api/v1/token/plextoken", "application/json", bytes.NewBuffer(req_body))
		
		if err != nil {
			return fmt.Errorf("Response error: %s", err)
		}

		defer resp.Body.Close()
		
		res_body, err := ioutil.ReadAll(resp.Body)
		
		if err != nil {
			return fmt.Errorf("Response READ error: %s", err)
		}
		
		s.logger.Debug("kodiak response_body", zap.String("res_body",string(res_body)))
		
		return handler.ServeHTTP(w, req) 
	}
	
	return handler.ServeHTTP(w, req)
}
	
func (s *plexsso) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	d.NextArg()
	
	for d.NextBlock(0) {	
		var err error
		
		switch d.Val() {
			case "token":
				err = parseStringArg(d, &s.plex_token)
			default:
				return d.Errf("Unknown plexsso arg")
			}
			if err != nil {
				return d.Errf("Error parsing %s: %s", d.Val(), err)
		}
	}
	return nil
}

var (
	_ caddy.Provisioner           = (*plexsso)(nil)
	_ caddyhttp.MiddlewareHandler = (*plexsso)(nil)
	_ caddyfile.Unmarshaler       = (*plexsso)(nil)
)
