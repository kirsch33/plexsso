# plexsso for Caddy v2

This module is aimed at bypassing the login portal for Ombi when combined with Paul Greenberg's caddy-auth-portal plugin. It compares the "X-Token-Subject" header to the value passed as username in plexsso setup. See example usage below:
## Syntax
```Caddyfile
#defining jwt object before plexsso
jwt {
  enable claim headers
  user_identity subject
}

plexsso {
  user USER_NAME PLEX_TOKEN
  host ombi.example.net
  referer https://example.net/auth/portal/
}
```
  
It is required to create the plexsso object after the jwt object in your Caddyfile and to enable claim headers as shown above. 
