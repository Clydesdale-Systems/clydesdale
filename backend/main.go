package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"golang.org/x/crypto/argon2"
)

type LoginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}
type SignupRequest struct {
	Email       string `json:"email"`
	Password    string `json:"password"`
	DisplayName string `json:"displayName"`
}

type LoginResponse struct {
	UserID      int64  `json:"userId"`
	DisplayName string `json:"displayName"`
	Email       string `json:"email"`
	Role        string `json:"role"`
}

var (
	db          *pgxpool.Pool
	sessionTTL  = 30 * 24 * time.Hour
	allowOrigin string
	cookieDomain string
)

func main() {
	// Env
	allowOrigin = os.Getenv("ALLOW_ORIGIN")
	if v := os.Getenv("SESSION_TTL_DAYS"); v != "" {
		if d, err := strconv.Atoi(v); err == nil && d > 0 {
			sessionTTL = time.Duration(d) * 24 * time.Hour
		}
	}
	cookieDomain = os.Getenv("COOKIE_DOMAIN")

	// DB
	dsn := getEnv("DB_DSN", "")
	if dsn == "" {
		log.Fatal("DB_DSN is required")
	}
	pool, err := pgxpool.New(context.Background(), dsn)
	if err != nil {
		log.Fatalf("db connect: %v", err)
	}
	db = pool
	defer db.Close()

	addr := getEnv("API_ADDR", ":8081")

	mux := http.NewServeMux()
	mux.HandleFunc("/api/health", handleHealth)

	// Auth
	mux.HandleFunc("/api/auth/signup", handleSignup)
	mux.HandleFunc("/api/auth/login", handleLogin)
	mux.HandleFunc("/api/auth/logout", handleLogout)
	mux.HandleFunc("/api/auth/me", handleMe)

	log.Printf("API listening on %s", addr)
	if err := http.ListenAndServe(addr, mux); err != nil {
		log.Fatal(err)
	}
}

// ---------- Handlers ----------

func handleHealth(w http.ResponseWriter, r *http.Request) {
	withCORS(w, allowOrigin)
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("ok"))
}

func handleSignup(w http.ResponseWriter, r *http.Request) {
	withCORS(w, allowOrigin)
	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req SignupRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad json", http.StatusBadRequest)
		return
	}
	if req.Email == "" || req.Password == "" {
		http.Error(w, "email & password required", http.StatusBadRequest)
		return
	}

	hash, err := hashPassword(req.Password)
	if err != nil {
		http.Error(w, "hash error", http.StatusInternalServerError)
		return
	}

	var id int64
	err = db.QueryRow(
		r.Context(),
		`INSERT INTO users (email, password_hash, display_name)
		 VALUES (LOWER($1), $2, NULLIF($3,'')) RETURNING id`,
		req.Email, hash, req.DisplayName,
	).Scan(&id)
	if err != nil {
		// duplicate email?
		if strings.Contains(err.Error(), "unique") {
			http.Error(w, "email already exists", http.StatusConflict)
			return
		}
		http.Error(w, "db error", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusCreated)
	w.Write([]byte(`{"ok":true}`))
}

func handleLogin(w http.ResponseWriter, r *http.Request) {
	withCORS(w, allowOrigin)
	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req LoginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad json", http.StatusBadRequest)
		return
	}

	var (
		id           int64
		email        string
		displayName  *string
		role         string
		passwordHash string
	)
	err := db.QueryRow(r.Context(),
		`SELECT id, email, display_name, role, password_hash
		   FROM users
		  WHERE email = LOWER($1) AND is_active = TRUE`,
		req.Email,
	).Scan(&id, &email, &displayName, &role, &passwordHash)
	if err != nil {
		recordAttempt(r, req.Email, false)
		http.Error(w, "invalid credentials", http.StatusUnauthorized)
		return
	}
	if !verifyPassword(passwordHash, req.Password) {
		recordAttempt(r, req.Email, false)
		http.Error(w, "invalid credentials", http.StatusUnauthorized)
		return
	}

	// Create session
	token, err := randomToken(32)
	if err != nil {
		http.Error(w, "token error", http.StatusInternalServerError)
		return
	}
	ua := r.UserAgent()
	ip := clientIP(r)

	_, err = db.Exec(r.Context(),
		`INSERT INTO sessions (token, user_id, expires_at, user_agent, ip)
		 VALUES ($1, $2, now() + $3::interval, $4, $5)`,
		token, id, fmt.Sprintf("%f hours", sessionTTL.Hours()), ua, ip,
	)
	if err != nil {
		http.Error(w, "db error", http.StatusInternalServerError)
		return
	}

	// Set cookie
	http.SetCookie(w, &http.Cookie{
		Name:     "sid",
		Value:    token,
		Path:     "/",
		Domain:   cookieDomain,      
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Secure:   isHTTPS(r),      
		Expires:  time.Now().Add(sessionTTL),
	})

	recordAttempt(r, req.Email, true)

	resp := LoginResponse{
		UserID:      id,
		DisplayName: safeStr(displayName),
		Email:       email,
		Role:        role,
	}
	jsonResponse(w, resp)
}

func handleLogout(w http.ResponseWriter, r *http.Request) {
	withCORS(w, allowOrigin)
	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	c, err := r.Cookie("sid")
	if err == nil && c.Value != "" {
		db.Exec(r.Context(), `DELETE FROM sessions WHERE token=$1`, c.Value)
	}
	// Expire cookie
	http.SetCookie(w, &http.Cookie{
		Name:     "sid", Value: "", Path: "/",
		Domain:   cookieDomain, HttpOnly: true, SameSite: http.SameSiteLaxMode,
		Expires: time.Unix(0, 0), MaxAge: -1, Secure: isHTTPS(r),
	})
	w.Write([]byte(`{"ok":true}`))
}

func handleMe(w http.ResponseWriter, r *http.Request) {
	withCORS(w, allowOrigin)
	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	user, err := currentUser(r.Context(), r)
	if err != nil {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	jsonResponse(w, user)
}

// ---------- Helpers ----------

type Me struct {
	UserID      int64  `json:"userId"`
	DisplayName string `json:"displayName"`
	Email       string `json:"email"`
	Role        string `json:"role"`
}

func currentUser(ctx context.Context, r *http.Request) (*Me, error) {
	c, err := r.Cookie("sid")
	if err != nil || c.Value == "" {
		return nil, errors.New("no session")
	}
	var m Me
	err = db.QueryRow(ctx,
		`SELECT u.id, COALESCE(u.display_name,''), u.email, u.role
		   FROM sessions s
		   JOIN users u ON u.id = s.user_id
		  WHERE s.token = $1 AND s.expires_at > now()`,
		c.Value,
	).Scan(&m.UserID, &m.DisplayName, &m.Email, &m.Role)
	if err != nil {
		return nil, errors.New("invalid session")
	}
	return &m, nil
}

func recordAttempt(r *http.Request, email string, ok bool) {
	ip := clientIP(r)
	ua := r.UserAgent()
	db.Exec(r.Context(),
		`INSERT INTO login_attempts (email, success, ip, user_agent)
		 VALUES (LOWER($1), $2, $3, $4)`,
		email, ok, ip, ua,
	)
}

// Argon2id helpers (encode hash with parameters)
func hashPassword(pw string) (string, error) {
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	// Reasonable defaults for server (tune as needed)
	timeCost := uint32(1)
	memCost := uint32(64 * 1024) // 64MB
	threads := uint8(2)
	keyLen := uint32(32)

	hash := argon2.IDKey([]byte(pw), salt, timeCost, memCost, threads, keyLen)
	// format: argon2id$t=1$m=65536,p=2$salt$hash
	return fmt.Sprintf("argon2id$t=%d$m=%d,p=%d$%s$%s",
		timeCost, memCost, threads,
		hex.EncodeToString(salt), hex.EncodeToString(hash)), nil
}

func verifyPassword(stored, pw string) bool {
	// parse
	var algo string
	var t int
	var m int
	var p int
	var saltHex, hashHex string
	_, err := fmt.Sscanf(stored, "%3s2id$t=%d$m=%d,p=%d$%s$%s", &algo, &t, &m, &p, &saltHex, &hashHex)
	if err != nil {
		return false
	}
	salt, _ := hex.DecodeString(saltHex)
	want, _ := hex.DecodeString(hashHex)
	sum := argon2.IDKey([]byte(pw), salt, uint32(t), uint32(m), uint8(p), uint32(len(want)))
	return subtleConstEq(sum, want)
}

func subtleConstEq(a, b []byte) bool {
	if len(a) != len(b) { return false }
	var v byte
	for i := range a { v |= a[i] ^ b[i] }
	return v == 0
}

func randomToken(n int) (string, error) {
	buf := make([]byte, n)
	_, err := rand.Read(buf)
	if err != nil { return "", err }
	return hex.EncodeToString(buf), nil
}

func clientIP(r *http.Request) net.IP {
	xff := r.Header.Get("X-Forwarded-For")
	if xff != "" {
		parts := strings.Split(xff, ",")
		ip := strings.TrimSpace(parts[0])
		return net.ParseIP(ip)
	}
	host, _, _ := net.SplitHostPort(r.RemoteAddr)
	return net.ParseIP(host)
}

func jsonResponse(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(v)
}

func withCORS(w http.ResponseWriter, allowOrigin string) {
	if allowOrigin != "" { w.Header().Set("Access-Control-Allow-Origin", allowOrigin) } else { w.Header().Set("Access-Control-Allow-Origin", "*") }
	w.Header().Set("Access-Control-Allow-Methods", "GET,POST,OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
	w.Header().Set("Access-Control-Allow-Credentials", "true")
}

func isHTTPS(r *http.Request) bool {
	// When behind Cloudflare/ingress, trust X-Forwarded-Proto
	if strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https") { return true }
	return r.TLS != nil
}

func getEnv(k, def string) string {
	if v := os.Getenv(k); v != "" { return v }
	return def
}

func safeStr(p *string) string {
	if p == nil { return "" }
	return *p
}