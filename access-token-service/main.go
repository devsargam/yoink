package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
	"google.golang.org/api/gmail/v1"
)

var (
	oauthConfig *oauth2.Config
	oauthState  = "random-state-string"
)

func init() {
	clientID := os.Getenv("GOOGLE_CLIENT_ID")
	clientSecret := os.Getenv("GOOGLE_CLIENT_SECRET")

	if clientID == "" || clientSecret == "" {
		// Try multiple paths to find credentials.json
		credPaths := []string{
			"credentials.json",
			"../credentials.json",
		}

		var credFile []byte
		var credErr error
		for _, path := range credPaths {
			credFile, credErr = os.ReadFile(path)
			if credErr == nil {
				log.Printf("Loaded credentials from %s", path)
				break
			}
		}

		if credErr != nil {
			log.Fatalf("Failed to load credentials.json. Set GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET env vars, or ensure credentials.json exists: %v", credErr)
		}

		var creds struct {
			Web struct {
				ClientID     string `json:"client_id"`
				ClientSecret string `json:"client_secret"`
			} `json:"web"`
		}
		if err := json.Unmarshal(credFile, &creds); err != nil {
			log.Fatalf("Failed to parse credentials.json: %v", err)
		}
		clientID = creds.Web.ClientID
		clientSecret = creds.Web.ClientSecret

		if clientID == "" || clientSecret == "" {
			log.Fatalf("credentials.json is missing client_id or client_secret in 'web' section")
		}
	}

	oauthConfig = &oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		RedirectURL:  "http://localhost:8080/callback",
		Scopes:       []string{gmail.GmailReadonlyScope},
		Endpoint:     google.Endpoint,
	}
}

func main() {
	http.HandleFunc("/", handleHome)
	http.HandleFunc("/login", handleLogin)
	http.HandleFunc("/callback", handleCallback)

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	fmt.Printf("Server running at http://localhost:%s\n", port)
	fmt.Println("Go to /login to authenticate")
	log.Fatal(http.ListenAndServe(":"+port, nil))
}

func handleHome(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html")
	fmt.Fprint(w, `<a href="/login">Login with Google</a>`)
}

func handleLogin(w http.ResponseWriter, r *http.Request) {
	url := oauthConfig.AuthCodeURL(oauthState, oauth2.AccessTypeOffline, oauth2.ApprovalForce)
	http.Redirect(w, r, url, http.StatusTemporaryRedirect)
}

func handleCallback(w http.ResponseWriter, r *http.Request) {
	if r.URL.Query().Get("state") != oauthState {
		http.Error(w, "Invalid state", http.StatusBadRequest)
		return
	}

	code := r.URL.Query().Get("code")
	if code == "" {
		http.Error(w, "Code not found", http.StatusBadRequest)
		return
	}

	token, err := oauthConfig.Exchange(context.Background(), code)
	if err != nil {
		http.Error(w, fmt.Sprintf("Token exchange failed: %v", err), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"access_token":  token.AccessToken,
		"refresh_token": token.RefreshToken,
		"token_type":    token.TokenType,
		"expiry":        token.Expiry,
	})
}
