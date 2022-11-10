package provider

import (
	"context"
	"errors"
	"strings"

	"github.com/netlify/gotrue/conf"
	"golang.org/x/oauth2"
)

// Luxbs
type luxbsProvider struct {
	*oauth2.Config
	Host string
}

type luxbsUser struct {
	Name          string `json:"name"`
	Sub           string `json:"sub"`
	Email         string `json:"email"`
	EmailVerified bool   `json:"email_verified"`
}

// NewLuxbsProvider creates a Luxbs account provider.
func NewLuxbsProvider(ext conf.OAuthProviderConfiguration, scopes string) (OAuthProvider, error) {
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
		return nil, errors.New("unable to find URL for the Luxbs provider")
	}

	extURLlen := len(ext.URL)
	if ext.URL[extURLlen-1] == '/' {
		ext.URL = ext.URL[:extURLlen-1]
	}

	return &luxbsProvider{
		Config: &oauth2.Config{
			ClientID:     ext.ClientID,
			ClientSecret: ext.Secret,
			Endpoint: oauth2.Endpoint{
				AuthURL:  ext.URL + "/connect/authorize",
				TokenURL: ext.URL + "/connect/token",
			},
			RedirectURL: ext.RedirectURI,
			Scopes:      oauthScopes,
		},
		Host: ext.URL,
	}, nil
}

func (g luxbsProvider) GetOAuthToken(code string) (*oauth2.Token, error) {
	return g.Exchange(context.Background(), code)
}

func (g luxbsProvider) GetUserData(ctx context.Context, tok *oauth2.Token) (*UserProvidedData, error) {
	var u luxbsUser

	if err := makeRequest(ctx, tok, g.Config, g.Host+"/connect/userinfo", &u); err != nil {
		return nil, err
	}

	if u.Email == "" {
		return nil, errors.New("unable to find email with Luxbs provider")
	}

	return &UserProvidedData{
		Metadata: &Claims{
			Issuer:        g.Host,
			Subject:       u.Sub,
			Name:          u.Name,
			Email:         u.Email,
			EmailVerified: u.EmailVerified,

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
