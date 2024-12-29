package auth

import (
	"crypto/rand"
	"encoding/base64"

	"github.com/spf13/viper"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
)

type AuthProvider struct {
	Provider     string
	OAuth2Config oauth2.Config
}

type AuthProviderConfig struct {
	Google  AuthProvider
	Naver   AuthProvider
	Twitter AuthProvider
}

var config AuthProviderConfig

func generateStateString() (string, error) {
	b := make([]byte, 32) // 32 bytes
	_, err := rand.Read(b)
	if err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(b), nil
}

func loadAuthProvider() {
	if viper.IsSet("auth-provider.google") {
		clientId := viper.GetString("auth-provider.google.client-id")
		clientSecret := viper.GetString("auth-provider.google.client-secret")
		redirectUri := viper.GetString("auth-provider.google.redirect-uri")
		scopes := viper.GetStringSlice("auth-provider.google.scopes")
		oauth2Config := oauth2.Config{
			ClientID:     clientId,
			ClientSecret: clientSecret,
			RedirectURL:  redirectUri,
			Scopes:       scopes,
			Endpoint:     google.Endpoint,
		}

		config.Google = AuthProvider{
			Provider:     "google",
			OAuth2Config: oauth2Config,
		}
	}

	if viper.IsSet("auth-provider.naver") {
		clientId := viper.GetString("auth-provider.naver.client-id")
		clientSecret := viper.GetString("auth-provider.naver.client-secret")
		redirectUri := viper.GetString("auth-provider.naver.redirect-uri")
		scopes := viper.GetStringSlice("auth-provider.naver.scopes")
		oauth2Config := oauth2.Config{
			ClientID:     clientId,
			ClientSecret: clientSecret,
			RedirectURL:  redirectUri,
			Scopes:       scopes,
			Endpoint:     google.Endpoint,
		}

		config.Naver = AuthProvider{
			Provider:     "naver",
			OAuth2Config: oauth2Config,
		}
	}

}
