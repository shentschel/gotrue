package provider

import (
	"context"
	"errors"
	"github.com/netlify/gotrue/conf"
	"golang.org/x/oauth2"
	"strings"
)

// Custom
type CustomProvider struct {
	*oauth2.Config
	Host string
	Path string
}

type CustomUser struct {
	Name          string     `json:"name"`
	Sub           string     `json:"sub"`
	Email         string     `json:"email"`
	EmailVerified bool       `json:"email_verified"`
	Role          CustomRole `json:"role"`
}

type CustomRole struct {
	Principal string   `json:"Principal"`
	Roles     []string `json:"Roles"`
}

// NewCustomProvider creates a Custom account provider.
func NewCustomProvider(ext conf.OAuthProviderConfiguration, scopes string) (OAuthProvider, error) {
	if err := ext.Validate(); err != nil {
		return nil, err
	}

	oauthScopes := []string{
		"profile",
		"email",
	}

	if scopes != "" {
		oauthScopes = append(oauthScopes, strings.Split(scopes, ",")...)
	}

	if ext.URL == "" {
		return nil, errors.New("unable to find URL for the Keycloak provider")
	}

	extURLlen := len(ext.URL)
	if ext.URL[extURLlen-1] == '/' {
		ext.URL = ext.URL[:extURLlen-1]
	}

	return &CustomProvider{
		Config: &oauth2.Config{
			ClientID:     ext.ClientID,
			ClientSecret: ext.Secret,
			Endpoint: oauth2.Endpoint{
				AuthURL:  ext.URL + ext.Path + "/auth",
				TokenURL: ext.URL + ext.Path + "/token",
			},
			RedirectURL: ext.RedirectURI,
			Scopes:      oauthScopes,
		},
		Host: ext.URL,
		Path: ext.Path,
	}, nil
}

func (g CustomProvider) GetOAuthToken(code string) (*oauth2.Token, error) {
	return g.Exchange(context.Background(), code)
}

func (g CustomProvider) GetUserData(ctx context.Context, tok *oauth2.Token) (*UserProvidedData, error) {
	var u CustomUser

	if err := makeRequest(ctx, tok, g.Config, g.Host+g.Path+"/userinfo", &u); err != nil {
		return nil, err
	}

	if u.Email == "" {
		return nil, errors.New("unable to find email with Keycloak provider")
	}

	return &UserProvidedData{
		Metadata: &Claims{
			Issuer:        g.Host,
			Subject:       u.Sub,
			Name:          u.Name,
			Email:         u.Email,
			EmailVerified: u.EmailVerified,

			CustomClaims: map[string]interface{}{
				"role": u.Role,
			},

			// To be deprecated
			FullName:   u.Name,
			ProviderId: u.Sub,
		},
		Emails: []Email{{
			Email:    u.Email,
			Verified: u.EmailVerified,
			Primary:  true,
		}},
	}, nil

}
