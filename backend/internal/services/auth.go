package services

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"time"

	"github.com/etoosammy01/ScamGuard-AI/backend/internal/models"
	"github.com/etoosammy01/ScamGuard-AI/backend/internal/repository"
)

var ErrCredentials = errors.New("invalid credentials")
var ErrUnauthenticated = errors.New("unauthenticated")

type AccountStore interface {
	CreateUser(context.Context, string, string, string) error
	Credentials(context.Context, string) (models.User, string, error)
	CreateSession(context.Context, string, []byte, []byte, time.Time) error
	SessionIdentity(context.Context, []byte) (models.Identity, error)
	Revoke(context.Context, []byte) error
	Profile(context.Context, string) (models.User, error)
	UpdateProfile(context.Context, string, *string, *string) (models.User, error)
}
type Auth struct {
	Store     AccountStore
	Passwords *Passwords
	Lifetime  time.Duration
}

func (a *Auth) Register(ctx context.Context, name, email, password, confirmation string) error {
	name, err := ValidateName(name)
	if err != nil {
		return ErrInvalid
	}
	email, err = NormalizeEmail(email)
	if err != nil {
		return ErrInvalid
	}
	if ValidatePassword(password) != nil || password != confirmation {
		return ErrInvalid
	}
	hash, err := a.Passwords.Hash(ctx, password)
	if err != nil {
		return err
	}
	err = a.Store.CreateUser(ctx, name, email, hash)
	if errors.Is(err, repository.ErrDuplicate) {
		return nil
	}
	return err
}
func (a *Auth) Login(ctx context.Context, email, password, previous string) (models.User, string, time.Time, error) {
	var empty models.User
	email, err := NormalizeEmail(email)
	if err != nil || ValidatePassword(password) != nil {
		return empty, "", time.Time{}, ErrCredentials
	}
	u, hash, err := a.Store.Credentials(ctx, email)
	missing := errors.Is(err, repository.ErrNotFound)
	if err != nil && !missing {
		return empty, "", time.Time{}, err
	}
	if missing {
		hash = a.Passwords.dummy
	}
	valid, err := a.Passwords.Verify(ctx, password, hash)
	if err != nil {
		return empty, "", time.Time{}, err
	}
	if !valid || missing {
		return empty, "", time.Time{}, ErrCredentials
	}
	random := make([]byte, 32)
	if _, err = rand.Read(random); err != nil {
		return empty, "", time.Time{}, err
	}
	token := base64.RawURLEncoding.EncodeToString(random)
	expires := time.Now().UTC().Add(a.Lifetime)
	hashBytes := sha256.Sum256([]byte(token))
	old, _ := TokenHash(previous)
	if err = a.Store.CreateSession(ctx, u.ID, hashBytes[:], old, expires); err != nil {
		return empty, "", time.Time{}, err
	}
	return u, token, expires, nil
}
func TokenHash(token string) ([]byte, error) {
	decoded, err := base64.RawURLEncoding.DecodeString(token)
	if err != nil || len(decoded) != 32 || len(token) != 43 {
		return nil, ErrUnauthenticated
	}
	hash := sha256.Sum256([]byte(token))
	return hash[:], nil
}
func (a *Auth) Authenticate(ctx context.Context, token string) (models.Identity, error) {
	hash, err := TokenHash(token)
	if err != nil {
		return models.Identity{}, ErrUnauthenticated
	}
	identity, err := a.Store.SessionIdentity(ctx, hash)
	if errors.Is(err, repository.ErrNotFound) {
		return identity, ErrUnauthenticated
	}
	return identity, err
}
func (a *Auth) Profile(ctx context.Context, id string) (models.User, error) {
	user, err := a.Store.Profile(ctx, id)
	if errors.Is(err, repository.ErrNotFound) {
		return user, ErrUnauthenticated
	}
	return user, err
}

func (a *Auth) Logout(ctx context.Context, token string) error {
	hash, err := TokenHash(token)
	if err != nil {
		return nil
	}
	return a.Store.Revoke(ctx, hash)
}
func (a *Auth) UpdateProfile(ctx context.Context, id string, name, bio *string) (models.User, error) {
	if name == nil && bio == nil {
		return models.User{}, ErrInvalid
	}
	if name != nil {
		normalized, err := ValidateName(*name)
		if err != nil {
			return models.User{}, ErrInvalid
		}
		name = &normalized
	}
	if bio != nil && ValidateBio(*bio) != nil {
		return models.User{}, ErrInvalid
	}
	user, err := a.Store.UpdateProfile(ctx, id, name, bio)
	if errors.Is(err, repository.ErrNotFound) {
		return user, ErrUnauthenticated
	}
	return user, err
}
