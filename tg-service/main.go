package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"os/signal"
	"regexp"
	"strings"
	"time"

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
		credFile, err := os.ReadFile("../credentials.json")
		if err == nil {
			var creds struct {
				Web struct {
					ClientID     string `json:"client_id"`
					ClientSecret string `json:"client_secret"`
				} `json:"web"`
			}
			if err := json.Unmarshal(credFile, &creds); err == nil {
				clientID = creds.Web.ClientID
				clientSecret = creds.Web.ClientSecret
			}
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

	code := extractNetflixCode(email.Body)
	if code == "" {
		b.SendMessage(ctx, &bot.SendMessageParams{
			ChatID: chatID,
			Text:   "No Netflix code found in email",
		})
		return
	}

	b.SendMessage(ctx, &bot.SendMessageParams{
		ChatID: chatID,
		Text:   code,
	})
}

func extractNetflixCode(body string) string {
	// Match 4-digit code that appears after "Enter this code" pattern
	re := regexp.MustCompile(`(?:Enter this code[^\d]*|sign in\s*)(\d{4,6})`)
	matches := re.FindStringSubmatch(body)
	if len(matches) > 1 {
		return matches[1]
	}

	// Fallback: look for standalone 4-6 digit number on its own line
	re2 := regexp.MustCompile(`(?m)^\s*(\d{4,6})\s*$`)
	matches2 := re2.FindStringSubmatch(body)
	if len(matches2) > 1 {
		return matches2[1]
	}

	return ""
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
		return nil, fmt.Errorf("failed to refresh token: %v", err)
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

		// Check if from Netflix
		if !strings.Contains(from, "info@account.netflix.com") {
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
