package main

import (
	"context"
	"log"
	"log/slog"
	"net/http"
	"time"

	"github.com/labstack/echo/v4"

	"github.com/aetomala/jwtauth/examples/echo-example/middleware"
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
		Issuer:               "echo-example",
		Audience:             []string{"echo-example-api"},
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

	// Setup Echo router
	e := echo.New()

	// Middleware
	e.Use(echo.MiddlewareFunc(func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			c.Set("tokenService", mgr)
			return next(c)
		}
	}))

	// Metrics endpoint
	e.GET("/metrics", func(c echo.Context) error {
		pm.Handler().ServeHTTP(c.Response().Writer, c.Request())
		return nil
	})

	// Public endpoints
	e.POST("/login", issueTokensHandler(mgr))
	e.POST("/refresh", refreshHandler(mgr))

	// Health check
	e.GET("/health", healthHandler)

	// Protected endpoints
	protected := e.Group("/api")
	protected.Use(middleware.BearerMiddleware(mgr))
	protected.GET("/profile", profileHandler)
	protected.POST("/logout", logoutHandler(mgr))

	log.Println("Starting server on :8080")
	if err := e.Start(":8080"); err != nil && err != http.ErrServerClosed {
		log.Fatal(err)
	}
}

// LoginRequest is the request body for login
type LoginRequest struct {
	UserID string `json:"user_id"`
}

// TokenResponse is the response body for token operations
type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token,omitempty"`
	ExpiresIn    int    `json:"expires_in"`
}

// issueTokensHandler issues a new token pair
func issueTokensHandler(mgr *tokens.Manager) echo.HandlerFunc {
	return func(c echo.Context) error {
		var req LoginRequest
		if err := c.Bind(&req); err != nil {
			return c.JSON(http.StatusBadRequest, map[string]string{
				"error": "invalid request body",
			})
		}

		if req.UserID == "" {
			return c.JSON(http.StatusBadRequest, map[string]string{
				"error": "user_id is required",
			})
		}

		ctx, cancel := context.WithTimeout(c.Request().Context(), 5*time.Second)
		defer cancel()

		accessToken, refreshToken, err := mgr.IssueTokenPair(ctx, req.UserID)
		if err != nil {
			return c.JSON(http.StatusInternalServerError, map[string]string{
				"error": "failed to issue tokens",
			})
		}

		return c.JSON(http.StatusOK, TokenResponse{
			AccessToken:  accessToken,
			RefreshToken: refreshToken,
			ExpiresIn:    900, // 15 minutes
		})
	}
}

// RefreshRequest is the request body for token refresh
type RefreshRequest struct {
	RefreshToken string `json:"refresh_token"`
}

// refreshHandler refreshes an access token
func refreshHandler(mgr *tokens.Manager) echo.HandlerFunc {
	return func(c echo.Context) error {
		var req RefreshRequest
		if err := c.Bind(&req); err != nil {
			return c.JSON(http.StatusBadRequest, map[string]string{
				"error": "invalid request body",
			})
		}

		if req.RefreshToken == "" {
			return c.JSON(http.StatusBadRequest, map[string]string{
				"error": "refresh_token is required",
			})
		}

		ctx, cancel := context.WithTimeout(c.Request().Context(), 5*time.Second)
		defer cancel()

		accessToken, err := mgr.RefreshAccessToken(ctx, req.RefreshToken)
		if err != nil {
			return c.JSON(http.StatusUnauthorized, map[string]string{
				"error": "failed to refresh token",
			})
		}

		return c.JSON(http.StatusOK, TokenResponse{
			AccessToken: accessToken,
			ExpiresIn:   900, // 15 minutes
		})
	}
}

// profileHandler returns the authenticated user's profile
func profileHandler(c echo.Context) error {
	userID := c.Get("userID")
	if userID == nil {
		return c.JSON(http.StatusUnauthorized, map[string]string{
			"error": "user not found in context",
		})
	}

	return c.JSON(http.StatusOK, map[string]interface{}{
		"user_id": userID,
		"message": "This is a protected endpoint",
	})
}

// logoutHandler revokes the user's tokens
func logoutHandler(mgr *tokens.Manager) echo.HandlerFunc {
	return func(c echo.Context) error {
		userID := c.Get("userID")
		if userID == nil {
			return c.JSON(http.StatusUnauthorized, map[string]string{
				"error": "user not found in context",
			})
		}

		ctx, cancel := context.WithTimeout(c.Request().Context(), 5*time.Second)
		defer cancel()

		if err := mgr.RevokeAllUserTokens(ctx, userID.(string)); err != nil {
			return c.JSON(http.StatusInternalServerError, map[string]string{
				"error": "failed to revoke tokens",
			})
		}

		return c.JSON(http.StatusOK, map[string]string{
			"message": "logged out successfully",
		})
	}
}

// healthHandler returns the health status
func healthHandler(c echo.Context) error {
	return c.JSON(http.StatusOK, map[string]string{
		"status": "healthy",
	})
}
