package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/go-telegram/bot"
	"github.com/go-telegram/bot/models"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
	"google.golang.org/api/gmail/v1"
	"google.golang.org/api/option"
)

type TokenJSON struct {
	AccessToken  string    `json:"access_token"`
	RefreshToken string    `json:"refresh_token"`
	TokenType    string    `json:"token_type"`
	Expiry       time.Time `json:"expiry"`
}

type Email struct {
	ID      string
	From    string
	Subject string
	Snippet string
	Date    string
	Body    string
}

var (
	gmailToken  TokenJSON
	oauthConfig *oauth2.Config
)

func main() {
	// Load Gmail token
	tokenData, err := os.ReadFile("token.json")
	if err != nil {
		log.Fatalf("Failed to read token.json: %v", err)
	}
	if err := json.Unmarshal(tokenData, &gmailToken); err != nil {
		log.Fatalf("Failed to parse token JSON: %v", err)
	}

	// Load OAuth credentials for token refresh
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
			log.Fatalf("Failed to load credentials.json from any location. Set GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET env vars, or ensure credentials.json exists: %v", credErr)
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
			log.Fatal("credentials.json is missing client_id or client_secret in 'web' section")
		}
	}

	oauthConfig = &oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		Endpoint:     google.Endpoint,
		Scopes:       []string{gmail.GmailReadonlyScope},
	}

	// Get Telegram bot token
	botToken := os.Getenv("TELEGRAM_BOT_TOKEN")
	if botToken == "" {
		log.Fatal("TELEGRAM_BOT_TOKEN environment variable not set")
	}

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()

	opts := []bot.Option{
		bot.WithDefaultHandler(defaultHandler),
	}

	b, err := bot.New(botToken, opts...)
	if err != nil {
		log.Fatalf("Failed to create bot: %v", err)
	}

	b.RegisterHandler(bot.HandlerTypeMessageText, "/emails", bot.MatchTypeExact, emailsHandler)

	log.Println("Bot started. Send /emails to get your latest 5 emails.")
	b.Start(ctx)
}

func emailsHandler(ctx context.Context, b *bot.Bot, update *models.Update) {
	chatID := update.Message.Chat.ID

	email, err := ReadNetflixEmail(gmailToken)
	if err != nil {
		b.SendMessage(ctx, &bot.SendMessageParams{
			ChatID: chatID,
			Text:   err.Error(),
		})
		return
	}

	messageText := strings.TrimSpace(email.Body)
	if messageText == "" {
		messageText = strings.TrimSpace(email.Snippet)
	}
	if messageText == "" {
		messageText = "Email body was empty."
	}

	b.SendMessage(ctx, &bot.SendMessageParams{
		ChatID: chatID,
		Text:   truncateTelegramMessage(messageText),
	})
}

const telegramMessageLimit = 4096

func truncateTelegramMessage(s string) string {
	if utf8.RuneCountInString(s) <= telegramMessageLimit {
		return s
	}
	runes := []rune(s)
	if len(runes) <= telegramMessageLimit {
		return s
	}
	return string(runes[:telegramMessageLimit-3]) + "..."
}

func defaultHandler(ctx context.Context, b *bot.Bot, update *models.Update) {
	if update.Message == nil {
		return
	}
	log.Printf("Received message: %s", update.Message.Text)
	b.SendMessage(ctx, &bot.SendMessageParams{
		ChatID: update.Message.Chat.ID,
		Text:   "Say /emails",
	})
}

func escapeMarkdown(s string) string {
	replacer := strings.NewReplacer(
		"_", "\\_",
		"*", "\\*",
		"[", "\\[",
		"]", "\\]",
		"`", "\\`",
	)
	return replacer.Replace(s)
}

func ReadNetflixEmail(tokenJSON TokenJSON) (*Email, error) {
	ctx := context.Background()

	token := &oauth2.Token{
		AccessToken:  tokenJSON.AccessToken,
		RefreshToken: tokenJSON.RefreshToken,
		TokenType:    tokenJSON.TokenType,
		Expiry:       tokenJSON.Expiry,
	}

	// TokenSource will auto-refresh when expired
	tokenSource := oauthConfig.TokenSource(ctx, token)

	// Get potentially refreshed token and save it
	newToken, err := tokenSource.Token()
	if err != nil {
		errStr := err.Error()
		if strings.Contains(errStr, "invalid_client") {
			return nil, fmt.Errorf("Token expired! Your refresh token has expired (this happens after 7 days in testing mode). Please run access-token-service and get a new token from /login")
		}
		if strings.Contains(errStr, "invalid_grant") {
			return nil, fmt.Errorf("Token revoked or expired. Please run access-token-service and get a new token from /login")
		}
		return nil, fmt.Errorf("Failed to refresh token: %v", err)
	}

	// If token was refreshed, update our stored token and save to file
	if newToken.AccessToken != token.AccessToken {
		gmailToken.AccessToken = newToken.AccessToken
		gmailToken.Expiry = newToken.Expiry
		if newToken.RefreshToken != "" {
			gmailToken.RefreshToken = newToken.RefreshToken
		}
		saveToken()
	}

	client := oauth2.NewClient(ctx, tokenSource)

	srv, err := gmail.NewService(ctx, option.WithHTTPClient(client))
	if err != nil {
		return nil, fmt.Errorf("unable to create Gmail service: %v", err)
	}

	messagesResponse, err := srv.Users.Messages.List("me").MaxResults(5).Do()
	if err != nil {
		return nil, fmt.Errorf("unable to list messages: %v", err)
	}

	if len(messagesResponse.Messages) == 0 {
		return nil, fmt.Errorf("no emails found")
	}

	for _, msg := range messagesResponse.Messages {
		message, err := srv.Users.Messages.Get("me", msg.Id).Format("full").Do()
		if err != nil {
			continue
		}

		var from string
		for _, header := range message.Payload.Headers {
			if header.Name == "From" {
				from = header.Value
				break
			}
		}

		// Check if email address mentions Netflix (case-insensitive)
		if !strings.Contains(strings.ToLower(from), "netflix") {
			continue
		}

		email := &Email{
			ID:      message.Id,
			Snippet: message.Snippet,
			From:    from,
		}

		for _, header := range message.Payload.Headers {
			switch header.Name {
			case "Subject":
				email.Subject = header.Value
			case "Date":
				email.Date = header.Value
			}
		}

		email.Body = getEmailBody(message.Payload)

		return email, nil
	}

	return nil, fmt.Errorf("No recent emails from Netflix")
}

func getEmailBody(payload *gmail.MessagePart) string {
	if payload.Body != nil && payload.Body.Data != "" {
		return decodeBase64(payload.Body.Data)
	}

	// Look for text/plain part first
	for _, part := range payload.Parts {
		if part.MimeType == "text/plain" && part.Body != nil && part.Body.Data != "" {
			return decodeBase64(part.Body.Data)
		}
	}

	// Check nested parts
	for _, part := range payload.Parts {
		if part.MimeType == "multipart/alternative" {
			for _, subpart := range part.Parts {
				if subpart.MimeType == "text/plain" && subpart.Body != nil && subpart.Body.Data != "" {
					return decodeBase64(subpart.Body.Data)
				}
			}
		}
	}

	return ""
}

func decodeBase64(data string) string {
	// Gmail uses URL-safe base64
	data = strings.ReplaceAll(data, "-", "+")
	data = strings.ReplaceAll(data, "_", "/")

	decoded, err := base64.StdEncoding.DecodeString(data)
	if err != nil {
		return ""
	}
	return string(decoded)
}

func saveToken() {
	data, err := json.MarshalIndent(gmailToken, "", "  ")
	if err != nil {
		log.Printf("Failed to marshal token: %v", err)
		return
	}
	if err := os.WriteFile("token.json", data, 0600); err != nil {
		log.Printf("Failed to save token: %v", err)
		return
	}
	log.Println("Token refreshed and saved")
}
