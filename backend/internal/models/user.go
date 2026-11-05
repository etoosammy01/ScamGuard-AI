package models

import "time"

// User is the public account representation. It never contains password/session hashes.
type User struct {
	ID        string    `json:"id"`
	FullName  string    `json:"full_name"`
	Email     string    `json:"email"`
	Bio       string    `json:"bio"`
	Role      string    `json:"role"`
	CreatedAt time.Time `json:"created_at"`
}

// Identity is the minimal server-derived authorization context.
type Identity struct {
	ID   string
	Role string
}

const IdentityKey = "scamguard.identity"
