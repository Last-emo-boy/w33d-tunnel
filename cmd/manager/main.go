package main

import (
	"encoding/json"
	"fmt"
	"math/rand"
	"net/http"
	"os"
	"sync"
	"time"

	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

// Models
type User struct {
	ID        uint      `gorm:"primaryKey" json:"id"`
	Username  string    `gorm:"unique" json:"username"`
	Token     string    `gorm:"unique;index" json:"token"`
	CreatedAt time.Time `json:"created_at"`
	QuotaBytes int64    `json:"quota_bytes"`
}

type Node struct {
	ID        string    `gorm:"primaryKey" json:"id"`
	Name      string    `json:"name"`
	Addr      string    `json:"addr"` // host:port
	PubKey    string    `json:"pub_key"`
	LastSeen  time.Time `json:"last_seen"`
}

type TrafficLog struct {
	ID        uint      `gorm:"primaryKey"`
	NodeID    string    `json:"node_id"`
	UserToken string    `index" json:"user_token"`
	BytesRead uint64    `json:"bytes_read"`
	BytesWritten uint64 `json:"bytes_written"`
	Timestamp time.Time `index" json:"timestamp"`
}

// Global DB
var db *gorm.DB

func main() {
	var err error
	// Ensure data directory exists
	os.MkdirAll("data", 0755)
	db, err = gorm.Open(sqlite.Open("data/manager.db"), &gorm.Config{})
	if err != nil {
		panic("failed to connect database")
	}

	// Migrate
	db.AutoMigrate(&User{}, &Node{}, &TrafficLog{})

	// Seed Dummy User
	var count int64
	db.Model(&User{}).Count(&count)
	if count == 0 {
		db.Create(&User{
			Username: "admin",
			Token:    "admin-token-123",
			QuotaBytes: 10 * 1024 * 1024 * 1024, // 10GB
		})
		fmt.Println("Created default user: admin / admin-token-123")
	}

	// CORS Middleware
	corsHandler := func(h http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Access-Control-Allow-Origin", "*")
			w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
			w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
			if r.Method == "OPTIONS" {
				return
			}
			h(w, r)
		}
	}

	// Routes
	http.HandleFunc("/api/report", corsHandler(handleReport))
	http.HandleFunc("/api/subscribe", corsHandler(handleSubscribe))
	http.HandleFunc("/api/nodes", corsHandler(handleNodes))
	http.HandleFunc("/api/stats", corsHandler(handleStats))
	http.HandleFunc("/api/register_node", corsHandler(handleRegisterNode))
	
	// Admin Routes
	http.HandleFunc("/api/admin/users", corsHandler(handleAdminUsers))
	http.HandleFunc("/api/admin/login", corsHandler(handleAdminLogin))

	fmt.Println("Manager listening on :3000")
	http.ListenAndServe(":3000", corsHandler(http.NotFound))
}

// Handlers

func handleAdminLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", 405)
		return
	}
	var payload struct {
		Token string `json:"token"`
	}
	json.NewDecoder(r.Body).Decode(&payload)
	
	// Simple check: Is this the admin user?
	var user User
	if err := db.First(&user, "token = ? AND username = 'admin'", payload.Token).Error; err != nil {
		http.Error(w, "Invalid admin token", 401)
		return
	}
	
	w.WriteHeader(200)
	json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}

func handleAdminUsers(w http.ResponseWriter, r *http.Request) {
	// Auth Check (Header: X-Admin-Token)
	adminToken := r.Header.Get("X-Admin-Token")
	var admin User
	if err := db.First(&admin, "token = ? AND username = 'admin'", adminToken).Error; err != nil {
		http.Error(w, "Unauthorized", 401)
		return
	}

	if r.Method == "GET" {
		var users []User
		db.Find(&users)
		json.NewEncoder(w).Encode(users)
		return
	}
	
	if r.Method == "POST" {
		var payload struct {
			Username string `json:"username"`
			QuotaGB  int64  `json:"quota_gb"`
		}
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
		
		// Generate Token
		token := fmt.Sprintf("u-%d-%s", time.Now().Unix(), randString(8))
		
		user := User{
			Username:   payload.Username,
			Token:      token,
			CreatedAt:  time.Now(),
			QuotaBytes: payload.QuotaGB * 1024 * 1024 * 1024,
		}
		
		if err := db.Create(&user).Error; err != nil {
			http.Error(w, "Failed to create user (duplicate?)", 400)
			return
		}
		
		json.NewEncoder(w).Encode(user)
		return
	}
}

func randString(n int) string {
	const letters = "abcdefghijklmnopqrstuvwxyz0123456789"
	b := make([]byte, n)
	for i := range b {
		b[i] = letters[rand.Intn(len(letters))]
	}
	return string(b)
}

func handleRegisterNode(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", 405)
		return
	}
	
	var payload struct {
		ID     string `json:"id"`
		Name   string `json:"name"`
		Addr   string `json:"addr"`
		PubKey string `json:"pub_key"`
	}
	
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		http.Error(w, err.Error(), 400)
		return
	}
	
	// Upsert Node
	var node Node
	if result := db.First(&node, "id = ?", payload.ID); result.Error != nil {
		db.Create(&Node{
			ID:       payload.ID,
			Name:     payload.Name,
			Addr:     payload.Addr,
			PubKey:   payload.PubKey,
			LastSeen: time.Now(),
		})
	} else {
		db.Model(&node).Updates(map[string]interface{}{
			"Name":     payload.Name,
			"Addr":     payload.Addr,
			"PubKey":   payload.PubKey,
			"LastSeen": time.Now(),
		})
	}
	
	w.WriteHeader(200)
}

func handleSubscribe(w http.ResponseWriter, r *http.Request) {
	token := r.URL.Query().Get("token")
	if token == "" {
		http.Error(w, "Token required", 400)
		return
	}

	var user User
	if err := db.First(&user, "token = ?", token).Error; err != nil {
		http.Error(w, "Invalid token", 403)
		return
	}

	// Return Nodes Config
	var nodes []Node
	db.Find(&nodes)

	// Format as JSON or specialized config
	// Let's return JSON for our frontend/client
	json.NewEncoder(w).Encode(map[string]interface{}{
		"user": user,
		"nodes": nodes,
	})
}

func handleNodes(w http.ResponseWriter, r *http.Request) {
	// Public endpoint? Or auth required?
	// Let's require auth for now?
	// For frontend dashboard, maybe public list is fine?
	var nodes []Node
	db.Find(&nodes)
	json.NewEncoder(w).Encode(nodes)
}

func handleStats(w http.ResponseWriter, r *http.Request) {
	token := r.URL.Query().Get("token")
	if token == "" {
		http.Error(w, "Token required", 400)
		return
	}

	// Aggregate
	var totalRead, totalWrite uint64
	
	type Result struct {
		R uint64
		W uint64
	}
	var res Result
	db.Model(&TrafficLog{}).Where("user_token = ?", token).
		Select("sum(bytes_read) as r, sum(bytes_written) as w").Scan(&res)
		
	json.NewEncoder(w).Encode(map[string]interface{}{
		"bytes_read": res.R,
		"bytes_written": res.W,
	})
}
