package handlers

import (
	"errors"
	"io"
	"mime"
	"net/http"
	"time"

	"github.com/etoosammy01/ScamGuard-AI/backend/internal/config"
	"github.com/etoosammy01/ScamGuard-AI/backend/internal/models"
	"github.com/etoosammy01/ScamGuard-AI/backend/internal/services"
	"github.com/etoosammy01/ScamGuard-AI/backend/internal/strictjson"
	"github.com/gin-gonic/gin"
)

type Auth struct {
	Service *services.Auth
	Config  config.Config
}

func decode(c *gin.Context, value any) bool {
	media, _, err := mime.ParseMediaType(c.GetHeader("Content-Type"))
	if err != nil || media != "application/json" {
		Error(c, 415, "unsupported_media_type", "Use application/json")
		return false
	}
	c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, 16*1024)
	data, err := io.ReadAll(c.Request.Body)
	if err != nil || strictjson.Decode(data, value) != nil {
		Error(c, 400, "invalid_input", "Send one unambiguous JSON object with valid fields")
		return false
	}
	return true
}
func authError(c *gin.Context, err error) {
	switch {
	case errors.Is(err, services.ErrInvalid):
		Error(c, 400, "invalid_input", "Check the submitted fields")
	case errors.Is(err, services.ErrCredentials):
		Error(c, 401, "invalid_credentials", "Email or password is incorrect")
	case errors.Is(err, services.ErrUnauthenticated):
		Error(c, 401, "unauthenticated", "Sign in to continue")
	case errors.Is(err, services.ErrBusy):
		c.Header("Retry-After", "5")
		Error(c, 429, "rate_limited", "Too many attempts. Try again later")
	default:
		Error(c, 503, "service_unavailable", "Service temporarily unavailable")
	}
}
func (a *Auth) Register(c *gin.Context) {
	var body struct {
		FullName        string `json:"full_name"`
		Email           string `json:"email"`
		Password        string `json:"password"`
		ConfirmPassword string `json:"confirm_password"`
	}
	if !decode(c, &body) {
		return
	}
	if err := a.Service.Register(c.Request.Context(), body.FullName, body.Email, body.Password, body.ConfirmPassword); err != nil {
		authError(c, err)
		return
	}
	c.JSON(202, gin.H{"message": "If this address is eligible, your account has been created. You can now try signing in."})
}
func (a *Auth) Login(c *gin.Context) {
	var body struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}
	if !decode(c, &body) {
		return
	}
	previous, _ := c.Cookie(a.Config.CookieName())
	user, token, expires, err := a.Service.Login(c.Request.Context(), body.Email, body.Password, previous)
	if err != nil {
		authError(c, err)
		return
	}
	http.SetCookie(c.Writer, &http.Cookie{Name: a.Config.CookieName(), Value: token, Path: "/", HttpOnly: true, Secure: a.Config.SecureCookies, SameSite: http.SameSiteLaxMode, Expires: expires, MaxAge: int(a.Config.SessionLifetime.Seconds())})
	c.JSON(200, gin.H{"user": user})
}
func (a *Auth) Logout(c *gin.Context) {
	token, _ := c.Cookie(a.Config.CookieName())
	if err := a.Service.Logout(c.Request.Context(), token); err != nil {
		authError(c, err)
		return
	}
	http.SetCookie(c.Writer, &http.Cookie{Name: a.Config.CookieName(), Value: "", Path: "/", HttpOnly: true, Secure: a.Config.SecureCookies, SameSite: http.SameSiteLaxMode, Expires: time.Unix(1, 0), MaxAge: -1})
	c.Status(204)
}
func (a *Auth) Me(c *gin.Context) {
	identity := c.MustGet(models.IdentityKey).(models.Identity)
	user, err := a.Service.Profile(c.Request.Context(), identity.ID)
	if err != nil {
		authError(c, err)
		return
	}
	c.JSON(200, gin.H{"user": user})
}
func (a *Auth) UpdateProfile(c *gin.Context) {
	var body struct {
		FullName *string `json:"full_name"`
		Bio      *string `json:"bio"`
	}
	if !decode(c, &body) {
		return
	}
	identity := c.MustGet(models.IdentityKey).(models.Identity)
	user, err := a.Service.UpdateProfile(c.Request.Context(), identity.ID, body.FullName, body.Bio)
	if err != nil {
		authError(c, err)
		return
	}
	c.JSON(200, gin.H{"user": user})
}
