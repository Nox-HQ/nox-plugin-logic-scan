package main

import (
	"encoding/json"
	"net/http"
)

// Vulnerable Go app for testing business logic flaw detection.

func main() {
	r := http.NewServeMux()
	r.HandleFunc("/api/users/{id}", getUser)
	r.HandleFunc("/api/admin/users", listUsers)
	r.HandleFunc("/api/users/{id}/update", updateUser)
}

// Fetches user by ID without verifying ownership.
func getUser(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	user := db.FindUser(id)
	json.NewEncoder(w).Encode(user)
}

// No access control on administrative endpoint.
func listUsers(w http.ResponseWriter, r *http.Request) {
	users := db.AllUsers()
	json.NewEncoder(w).Encode(users)
}

// Binds entire request body to user struct without filtering fields.
func updateUser(w http.ResponseWriter, r *http.Request) {
	var user User
	json.NewDecoder(r.Body).Decode(&user)
	db.Save(user)
	w.WriteHeader(http.StatusOK)
}
