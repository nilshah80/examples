package main

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"sync"
	"time"
)

//go:embed static/index.html
var indexHTML string

//go:embed static/css/style.css
var styleCSS string

// JourneyState holds mutable state protected by mutex.
type JourneyState struct {
	mu           sync.Mutex
	config       Config
	httpClient   *http.Client
	session      *SessionContext
	accessToken  string
	refreshToken string
}

func main() {
	config := LoadConfig()

	for _, arg := range os.Args[1:] {
		if arg == "--cli" {
			runCLI(config)
			return
		}
	}

	state := &JourneyState{
		config:     config,
		httpClient: &http.Client{},
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /{$}", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprint(w, indexHTML)
	})
	mux.HandleFunc("GET /css/style.css", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/css")
		fmt.Fprint(w, styleCSS)
	})
	mux.HandleFunc("POST /steps/1", state.handleStep1)
	mux.HandleFunc("POST /steps/2", state.handleStep2)
	mux.HandleFunc("POST /steps/3", state.handleStep3)
	mux.HandleFunc("POST /steps/4", state.handleStep4)
	mux.HandleFunc("POST /steps/5", state.handleStep5)
	mux.HandleFunc("POST /steps/6", state.handleStep6)
	mux.HandleFunc("POST /steps/reset", state.handleReset)

	addr := fmt.Sprintf("0.0.0.0:%d", config.Port)
	fmt.Println()
	fmt.Println("  Identity Service — External Client Example (Go)")
	fmt.Printf("  Web UI:  http://localhost:%d\n", config.Port)
	fmt.Println("  API:     /steps/1..6 → Go crypto → Sidecar")
	fmt.Println("  Auth:    HMAC-SHA256")
	fmt.Println()

	if err := http.ListenAndServe(addr, mux); err != nil {
		fmt.Fprintf(os.Stderr, "Server failed: %v\n", err)
		os.Exit(1)
	}
}

func writeJSON(w http.ResponseWriter, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(v)
}

func writeErrorJSON(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(map[string]string{"error": msg})
}

// -- Step Handlers --

func (s *JourneyState) handleStep1(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()

	start := time.Now()
	ctx, err := InitSession(&s.config, s.httpClient)
	if err != nil {
		errStr := err.Error()
		writeJSON(w, SessionResult{
			Step: 1, Name: "Session Init (Anonymous ECDH)",
			Success: false, DurationMs: time.Since(start).Milliseconds(),
			Error: &errStr,
		})
		return
	}
	result := SessionResult{
		Step: 1, Name: "Session Init (Anonymous ECDH)",
		Success: true, DurationMs: time.Since(start).Milliseconds(),
		SessionID: ctx.SessionID, Kid: ctx.Kid,
		Authenticated: ctx.Authenticated, ExpiresInSec: ctx.ExpiresInSec,
	}
	s.session = ctx
	s.accessToken = ""
	s.refreshToken = ""
	writeJSON(w, result)
}

func (s *JourneyState) handleStep2(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.session == nil {
		writeErrorJSON(w, http.StatusBadRequest, "Run step 1 first")
		return
	}

	body, _ := json.Marshal(map[string]interface{}{
		"audience":              "orders-api",
		"scope":                 "orders.read",
		"subject":               s.config.Subject,
		"include_refresh_token": true,
		"single_session":        true,
		"custom_claims": map[string]string{
			"partner_id": "P-1234",
			"region":     "APAC",
		},
	})

	result := IssueToken(&s.config, s.httpClient, s.session, string(body))

	if result.Success {
		var data map[string]interface{}
		if err := json.Unmarshal([]byte(result.ResponseBodyDecrypted), &data); err == nil {
			if at, ok := data["access_token"].(string); ok {
				s.accessToken = at
			}
			if rt, ok := data["refresh_token"].(string); ok {
				s.refreshToken = rt
			}
		}
	}

	writeJSON(w, result)
}

func (s *JourneyState) handleStep3(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.session == nil || s.accessToken == "" {
		writeErrorJSON(w, http.StatusBadRequest, "Run steps 1-2 first")
		return
	}

	body, _ := json.Marshal(map[string]string{"token": s.accessToken})
	result := IntrospectToken(&s.config, s.httpClient, s.session, string(body), s.accessToken)
	writeJSON(w, result)
}

func (s *JourneyState) handleStep4(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.session == nil || s.accessToken == "" {
		writeErrorJSON(w, http.StatusBadRequest, "Run steps 1-3 first")
		return
	}

	start := time.Now()
	ctx, err := RefreshSession(&s.config, s.httpClient, s.accessToken, s.session)
	if err != nil {
		errStr := err.Error()
		writeJSON(w, SessionResult{
			Step: 4, Name: "Session Refresh (Authenticated ECDH)",
			Success: false, DurationMs: time.Since(start).Milliseconds(),
			Error: &errStr,
		})
		return
	}
	result := SessionResult{
		Step: 4, Name: "Session Refresh (Authenticated ECDH)",
		Success: true, DurationMs: time.Since(start).Milliseconds(),
		SessionID: ctx.SessionID, Kid: ctx.Kid,
		Authenticated: ctx.Authenticated, ExpiresInSec: ctx.ExpiresInSec,
	}
	s.session = ctx
	writeJSON(w, result)
}

func (s *JourneyState) handleStep5(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.session == nil || s.accessToken == "" {
		writeErrorJSON(w, http.StatusBadRequest, "Run steps 1-4 first")
		return
	}

	body, _ := json.Marshal(map[string]string{
		"grant_type":    "refresh_token",
		"refresh_token": s.refreshToken,
	})
	result := RefreshToken(&s.config, s.httpClient, s.session, string(body), s.accessToken)

	if result.Success {
		var data map[string]interface{}
		if err := json.Unmarshal([]byte(result.ResponseBodyDecrypted), &data); err == nil {
			if at, ok := data["access_token"].(string); ok {
				s.accessToken = at
			}
			if rt, ok := data["refresh_token"].(string); ok {
				s.refreshToken = rt
			}
		}
	}

	writeJSON(w, result)
}

func (s *JourneyState) handleStep6(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.session == nil || s.accessToken == "" {
		writeErrorJSON(w, http.StatusBadRequest, "Run steps 1-5 first")
		return
	}

	body, _ := json.Marshal(map[string]string{
		"token":           s.refreshToken,
		"token_type_hint": "refresh_token",
	})
	result := RevokeToken(&s.config, s.httpClient, s.session, string(body), s.accessToken)
	writeJSON(w, result)
}

func (s *JourneyState) handleReset(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.session != nil {
		s.session.Zeroize()
	}
	s.session = nil
	s.accessToken = ""
	s.refreshToken = ""
	writeJSON(w, map[string]bool{"success": true})
}

// -- CLI Runner --

func runCLI(config Config) {
	const (
		RESET  = "\033[0m"
		BOLD   = "\033[1m"
		DIM    = "\033[2m"
		BLUE   = "\033[34m"
		GREEN  = "\033[32m"
		RED    = "\033[31m"
		CYAN   = "\033[36m"
		YELLOW = "\033[33m"
	)

	httpClient := &http.Client{}
	clientID := config.ClientID

	fmt.Println()
	fmt.Printf("%s%s  ╔══════════════════════════════════════════════════╗%s\n", YELLOW, BOLD, RESET)
	fmt.Printf("%s%s  ║  Identity Service — External Client (Go)         ║%s\n", YELLOW, BOLD, RESET)
	fmt.Printf("%s%s  ║  Auth: HMAC-SHA256 + AES-256-GCM                 ║%s\n", YELLOW, BOLD, RESET)
	fmt.Printf("%s%s  ║  Client: %-40s ║%s\n", YELLOW, BOLD, clientID, RESET)
	fmt.Printf("%s%s  ╚══════════════════════════════════════════════════╝%s\n", YELLOW, BOLD, RESET)
	fmt.Println()

	printResult := func(r *StepResult) {
		status := fmt.Sprintf("%s✓ Success", GREEN)
		if !r.Success {
			status = fmt.Sprintf("%s✗ Failed", RED)
		}
		fmt.Printf("    %s (%dms)%s\n", status, r.DurationMs, RESET)
		fmt.Printf("%s    Request Body (plaintext):%s\n", YELLOW, RESET)
		fmt.Printf("%s      %s%s\n", DIM, truncate(r.RequestBodyPlaintext, 200), RESET)
		fmt.Printf("%s    Response Body (decrypted):%s\n", YELLOW, RESET)
		fmt.Printf("%s      %s%s\n", DIM, truncate(r.ResponseBodyDecrypted, 200), RESET)
		if !r.Success && r.Error != nil {
			fmt.Printf("%s    Error: %s%s\n", RED, *r.Error, RESET)
		}
		fmt.Println()
	}

	// Step 1: Session Init
	fmt.Printf("%s%s  ── Step 1: Session Init (Anonymous ECDH) ──%s\n", CYAN, BOLD, RESET)
	sess, err := InitSession(&config, httpClient)
	if err != nil {
		fmt.Printf("%s    ✗ %s%s\n", RED, err, RESET)
		return
	}
	fmt.Printf("%s    ✓ Session established%s\n", GREEN, RESET)
	fmt.Printf("%s    SessionId: %s%s\n", DIM, sess.SessionID, RESET)
	fmt.Printf("%s    Kid:       %s%s\n", DIM, sess.Kid, RESET)
	authStr := "anonymous"
	if sess.Authenticated {
		authStr = "authenticated"
	}
	fmt.Printf("%s    TTL:       %ds (%s)%s\n", DIM, sess.ExpiresInSec, authStr, RESET)
	fmt.Println()

	// Step 2: Token Issue (HMAC-SHA256)
	fmt.Printf("%s%s  ── Step 2: Token Issue (HMAC-SHA256 + GCM) ──%s\n", CYAN, BOLD, RESET)
	issueBody, _ := json.Marshal(map[string]interface{}{
		"audience":              "orders-api",
		"scope":                 "orders.read",
		"subject":               config.Subject,
		"include_refresh_token": true,
		"single_session":        true,
		"custom_claims": map[string]string{
			"partner_id": "P-1234",
			"region":     "APAC",
		},
	})
	issueResult := IssueToken(&config, httpClient, sess, string(issueBody))
	printResult(&issueResult)
	if !issueResult.Success {
		return
	}
	var issueData map[string]interface{}
	json.Unmarshal([]byte(issueResult.ResponseBodyDecrypted), &issueData)
	accessToken := issueData["access_token"].(string)
	refreshToken := ""
	if rt, ok := issueData["refresh_token"].(string); ok {
		refreshToken = rt
	}

	// Step 3: Token Introspection
	fmt.Printf("%s%s  ── Step 3: Token Introspection (Bearer + GCM) ──%s\n", CYAN, BOLD, RESET)
	introBody, _ := json.Marshal(map[string]string{"token": accessToken})
	introResult := IntrospectToken(&config, httpClient, sess, string(introBody), accessToken)
	printResult(&introResult)
	if !introResult.Success {
		return
	}

	// Step 4: Session Refresh
	fmt.Printf("%s%s  ── Step 4: Session Refresh (Authenticated ECDH) ──%s\n", CYAN, BOLD, RESET)
	sess, err = RefreshSession(&config, httpClient, accessToken, sess)
	if err != nil {
		fmt.Printf("%s    ✗ %s%s\n", RED, err, RESET)
		return
	}
	fmt.Printf("%s    ✓ Session refreshed%s\n", GREEN, RESET)
	fmt.Printf("%s    SessionId: %s%s\n", DIM, sess.SessionID, RESET)
	fmt.Printf("%s    TTL:       %ds (authenticated)%s\n", DIM, sess.ExpiresInSec, RESET)
	fmt.Println()

	// Step 5: Token Refresh
	fmt.Printf("%s%s  ── Step 5: Token Refresh (Bearer + GCM) ──%s\n", CYAN, BOLD, RESET)
	refreshBody, _ := json.Marshal(map[string]string{
		"grant_type":    "refresh_token",
		"refresh_token": refreshToken,
	})
	refreshResult := RefreshToken(&config, httpClient, sess, string(refreshBody), accessToken)
	printResult(&refreshResult)
	if !refreshResult.Success {
		return
	}
	var refreshData map[string]interface{}
	json.Unmarshal([]byte(refreshResult.ResponseBodyDecrypted), &refreshData)
	accessToken = refreshData["access_token"].(string)
	if rt, ok := refreshData["refresh_token"].(string); ok {
		refreshToken = rt
	}

	// Step 6: Token Revocation
	fmt.Printf("%s%s  ── Step 6: Token Revocation (Bearer + GCM) ──%s\n", CYAN, BOLD, RESET)
	revokeBody, _ := json.Marshal(map[string]string{
		"token":           refreshToken,
		"token_type_hint": "refresh_token",
	})
	revokeResult := RevokeToken(&config, httpClient, sess, string(revokeBody), accessToken)
	printResult(&revokeResult)

	// Cleanup
	sess.Zeroize()
	fmt.Printf("%s%s  All 6 steps completed successfully!%s\n", GREEN, BOLD, RESET)
	fmt.Println()
}

func truncate(s string, max int) string {
	if s == "" {
		return "(empty)"
	}
	if len(s) > max {
		return s[:max] + "..."
	}
	return s
}
