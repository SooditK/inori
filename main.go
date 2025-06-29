package main

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/joho/godotenv"
	"github.com/redis/go-redis/v9"
	_ "github.com/tursodatabase/libsql-client-go/libsql"
)

var db *sql.DB
var rdb *redis.Client
var encryptionKey []byte
var useRedis bool

var rateLimiter = make(map[string]*RateLimit)
var mu sync.Mutex

type RateLimit struct {
	Requests int
	ResetAt  time.Time
}

const RateLimitWindow = time.Minute
const MaxRequestsPerWindow = 30

func main() {
	err := godotenv.Load(".env")
	if err != nil {
		log.Fatal("Error loading .env file")
	}

	dbURL := os.Getenv("LIBSQL_DB_URL")
	dbToken := os.Getenv("LIBSQL_DB_AUTH_TOKEN")
	masterKey := os.Getenv("MASTER_SECRET_KEY")
	redisURL := os.Getenv("REDIS_URL")

	if dbURL == "" || dbToken == "" {
		log.Fatal("LIBSQL_DB_URL and LIBSQL_DB_AUTH_TOKEN must be set")
	}

	if len(masterKey) != 64 {
		log.Fatal("MASTER_SECRET_KEY must be 64 hex characters (256-bit key)")
	}
	encryptionKeyBytes, err := hex.DecodeString(masterKey)
	if err != nil {
		log.Fatalf("Failed to decode MASTER_SECRET_KEY: %v", err)
	}
	encryptionKey = encryptionKeyBytes

	dsn := fmt.Sprintf("%s?authToken=%s", dbURL, dbToken)
	db, err = sql.Open("libsql", dsn)
	if err != nil {
		log.Fatalf("Failed to connect to LibSQL: %v", err)
	}

	if err := initSchema(); err != nil {
		log.Fatalf("Failed to initialize schema: %v", err)
	}

	if redisURL != "" {
		rdb = redis.NewClient(&redis.Options{
			Addr: redisURL,
		})
		useRedis = true
		log.Println("Redis enabled for caching and rate limiting.")
	} else {
		useRedis = false
		log.Println("Redis not configured; using in-memory cache and rate limiter.")
	}

	http.HandleFunc("/get", rateLimitMiddleware(getSecretHandler))
	http.HandleFunc("/set", rateLimitMiddleware(setSecretHandler))
	http.HandleFunc("/delete", rateLimitMiddleware(deleteSecretHandler))

	log.Println("Secrets Manager running on :8080")
	http.ListenAndServe(":8080", nil)
}

func initSchema() error {
	_, err := db.Exec(`
		CREATE TABLE IF NOT EXISTS secrets (
			key TEXT PRIMARY KEY,
			value TEXT NOT NULL,
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
		);
		CREATE TABLE IF NOT EXISTS audit_log (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			action TEXT NOT NULL,
			secret_key TEXT NOT NULL,
			timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			actor_token TEXT
		);
	`)
	return err
}

func encrypt(value string) (string, error) {
	block, err := aes.NewCipher(encryptionKey)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}

	ciphertext := gcm.Seal(nonce, nonce, []byte(value), nil)
	return hex.EncodeToString(ciphertext), nil
}

func decrypt(encrypted string) (string, error) {
	ciphertext, err := hex.DecodeString(encrypted)
	if err != nil {
		return "", err
	}
	block, err := aes.NewCipher(encryptionKey)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	if len(ciphertext) < gcm.NonceSize() {
		return "", errors.New("ciphertext too short")
	}
	nonce, ciphertext := ciphertext[:gcm.NonceSize()], ciphertext[gcm.NonceSize():]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", err
	}
	return string(plaintext), nil
}

func getSecretHandler(w http.ResponseWriter, r *http.Request) {
	key := r.URL.Query().Get("key")
	token := r.Header.Get("Authorization")
	if !isAuthorized(token) {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
	defer cancel()

	if useRedis {
		val, err := rdb.Get(ctx, key).Result()
		if err == nil {
			dec, err := decrypt(val)
			if err == nil {
				audit("read_cache", key, token)
				fmt.Fprint(w, dec)
				return
			}
		}
	}

	var encVal string
	err := db.QueryRowContext(ctx, "SELECT value FROM secrets WHERE key = ?", key).Scan(&encVal)
	if err != nil {
		http.Error(w, "Secret not found", http.StatusNotFound)
		return
	}

	decVal, err := decrypt(encVal)
	if err != nil {
		http.Error(w, "Decryption failed", http.StatusInternalServerError)
		return
	}

	if useRedis {
		_ = rdb.Set(ctx, key, encVal, time.Hour).Err()
	}

	audit("read_db", key, token)
	fmt.Fprint(w, decVal)
}

func setSecretHandler(w http.ResponseWriter, r *http.Request) {
	key := r.URL.Query().Get("key")
	value := r.URL.Query().Get("value")
	token := r.Header.Get("Authorization")
	if !isAuthorized(token) {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	encrypted, err := encrypt(value)
	if err != nil {
		http.Error(w, "Encryption failed", http.StatusInternalServerError)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
	defer cancel()

	_, err = db.ExecContext(ctx, "INSERT OR REPLACE INTO secrets(key, value) VALUES (?, ?)", key, encrypted)
	if err != nil {
		http.Error(w, "Storage failed", http.StatusInternalServerError)
		return
	}

	if useRedis {
		_ = rdb.Set(ctx, key, encrypted, time.Hour).Err()
	}

	audit("write", key, token)
	fmt.Fprint(w, "OK")
}

func deleteSecretHandler(w http.ResponseWriter, r *http.Request) {
	key := r.URL.Query().Get("key")
	token := r.Header.Get("Authorization")
	if !isAuthorized(token) {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
	defer cancel()

	_, err := db.ExecContext(ctx, "DELETE FROM secrets WHERE key = ?", key)
	if err != nil {
		http.Error(w, "Deletion failed", http.StatusInternalServerError)
		return
	}
	if useRedis {
		_ = rdb.Del(ctx, key).Err()
	}

	audit("delete", key, token)
	fmt.Fprint(w, "Deleted")
}

func audit(action, key, token string) {
	_, err := db.Exec("INSERT INTO audit_log(action, secret_key, actor_token) VALUES (?, ?, ?)", action, key, token)
	if err != nil {
		log.Printf("audit error: %v", err)
	}
}

func isAuthorized(token string) bool {
	return strings.TrimSpace(token) == os.Getenv("SECRETS_API_TOKEN")
}

func rateLimitMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ip, _, _ := net.SplitHostPort(r.RemoteAddr)
		ctx := r.Context()
		var key = "rate:" + ip

		if useRedis {
			count, err := rdb.Incr(ctx, key).Result()
			if err == nil && count == 1 {
				rdb.Expire(ctx, key, RateLimitWindow)
			}
			if count > int64(MaxRequestsPerWindow) {
				http.Error(w, "Rate limit exceeded", http.StatusTooManyRequests)
				return
			}
		} else {
			mu.Lock()
			rl, exists := rateLimiter[ip]
			if !exists || time.Now().After(rl.ResetAt) {
				rl = &RateLimit{Requests: 1, ResetAt: time.Now().Add(RateLimitWindow)}
				rateLimiter[ip] = rl
			} else {
				rl.Requests++
				if rl.Requests > MaxRequestsPerWindow {
					mu.Unlock()
					http.Error(w, "Rate limit exceeded", http.StatusTooManyRequests)
					return
				}
			}
			mu.Unlock()
		}
		next(w, r)
	}
}
