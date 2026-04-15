package main

import (
	"context"
	"log"
	"log/slog"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/aetomala/jwtauth/examples/gin-example/middleware"
	"github.com/aetomala/jwtauth/pkg/keymanager"
	"github.com/aetomala/jwtauth/pkg/logging"
	"github.com/aetomala/jwtauth/pkg/metrics"
	"github.com/aetomala/jwtauth/pkg/storage"
	"github.com/aetomala/jwtauth/pkg/tokens"
)

func main() {
	// Setup logger
	logger := logging.NewTextLogger(slog.LevelDebug)

	// Setup metrics
	pm := metrics.NewPrometheusMetrics(metrics.PrometheusConfig{})

	// Create KeyStore and KeyManager
	ks, err := keymanager.NewDiskKeyStore("./keys", 2048, logger, pm)
	if err != nil {
		log.Fatal("Failed to create DiskKeyStore:", err)
	}

	km, err := keymanager.NewManager(keymanager.ManagerConfig{
		KeyStore:            ks,
		KeyRotationInterval: 30 * 24 * time.Hour,
		Logger:              logger,
		Metrics:             pm,
	})
	if err != nil {
		log.Fatal("Failed to create KeyManager:", err)
	}

	ctx := context.Background()
	if err := km.Start(ctx); err != nil {
		log.Fatal("Failed to start KeyManager:", err)
	}
	defer func() {
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = km.Shutdown(shutdownCtx)
	}()

	// Create RefreshStore
	store := storage.NewMemoryRefreshStore(logger, pm)

	// Create TokenService
	mgr, err := tokens.NewManager(tokens.ManagerConfig{
		KeyManager:           km,
		RefreshStore:         store,
		AccessTokenDuration:  15 * time.Minute,
		RefreshTokenDuration: 7 * 24 * time.Hour,
		CleanupInterval:      1 * time.Hour,
		Logger:               logger,
		Metrics:              pm,
		Issuer:               "gin-example",
		Audience:             []string{"gin-example-api"},
	})
	if err != nil {
		log.Fatal("Failed to create TokenService:", err)
	}

	if err := mgr.Start(ctx); err != nil {
		log.Fatal("Failed to start TokenService:", err)
	}
	defer func() {
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = mgr.Shutdown(shutdownCtx)
	}()

	// Setup Gin router
	r := gin.Default()

	// Metrics endpoint
	r.GET("/metrics", gin.WrapH(pm.Handler()))

	// Public endpoints
	r.POST("/login", issueTokensHandler(mgr))
	r.POST("/refresh", refreshHandler(mgr))

	// Protected endpoints
	protected := r.Group("/api")
	protected.Use(middleware.BearerMiddleware(mgr))
	protected.GET("/profile", profileHandler)
	protected.POST("/logout", logoutHandler(mgr))

	// Health check
	r.GET("/health", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"status": "healthy"})
	})

	log.Println("Starting server on :8080")
	if err := r.Run(":8080"); err != nil {
		log.Fatal(err)
	}
}

// LoginRequest is the request body for login
type LoginRequest struct {
	UserID string `json:"user_id" binding:"required"`
}

// TokenResponse is the response body for token operations
type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token,omitempty"`
	ExpiresIn    int    `json:"expires_in"`
}

// issueTokensHandler issues a new token pair
func issueTokensHandler(mgr *tokens.Manager) gin.HandlerFunc {
	return func(c *gin.Context) {
		var req LoginRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		if req.UserID == "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "user_id is required"})
			return
		}

		ctx, cancel := context.WithTimeout(c.Request.Context(), 5*time.Second)
		defer cancel()

		accessToken, refreshToken, err := mgr.IssueTokenPair(ctx, req.UserID)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to issue tokens"})
			return
		}

		c.JSON(http.StatusOK, TokenResponse{
			AccessToken:  accessToken,
			RefreshToken: refreshToken,
			ExpiresIn:    900, // 15 minutes
		})
	}
}

// RefreshRequest is the request body for token refresh
type RefreshRequest struct {
	RefreshToken string `json:"refresh_token" binding:"required"`
}

// refreshHandler refreshes an access token
func refreshHandler(mgr *tokens.Manager) gin.HandlerFunc {
	return func(c *gin.Context) {
		var req RefreshRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		ctx, cancel := context.WithTimeout(c.Request.Context(), 5*time.Second)
		defer cancel()

		accessToken, err := mgr.RefreshAccessToken(ctx, req.RefreshToken)
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "failed to refresh token"})
			return
		}

		c.JSON(http.StatusOK, TokenResponse{
			AccessToken: accessToken,
			ExpiresIn:   900, // 15 minutes
		})
	}
}

// profileHandler returns the authenticated user's profile
func profileHandler(c *gin.Context) {
	userID, exists := c.Get("userID")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "user not found in context"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"user_id": userID,
		"message": "This is a protected endpoint",
	})
}

// logoutHandler revokes the user's tokens
func logoutHandler(mgr *tokens.Manager) gin.HandlerFunc {
	return func(c *gin.Context) {
		userID, exists := c.Get("userID")
		if !exists {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "user not found in context"})
			return
		}

		ctx, cancel := context.WithTimeout(c.Request.Context(), 5*time.Second)
		defer cancel()

		if err := mgr.RevokeAllUserTokens(ctx, userID.(string)); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to revoke tokens"})
			return
		}

		c.JSON(http.StatusOK, gin.H{"message": "logged out successfully"})
	}
}
