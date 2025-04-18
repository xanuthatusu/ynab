package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/xanuthatusu/ynab/pkg/postgres"
	"golang.org/x/crypto/bcrypt"
)

type Config struct {
	Port string
	Host string
}

func addMiddleware(
	handler http.Handler,
	logger *logrus.Logger,
) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		logger.Infof("[%s] %s", r.Method, r.URL.Path)
		handler.ServeHTTP(w, r)
	})
}

func addRoutes(
	mux *http.ServeMux,
	logger *logrus.Logger,
	pg *postgres.Postgres,
) {
	mux.HandleFunc("/user/{username}", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" {
			w.Write([]byte("wrong method"))
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		// return nil
		username := strings.Split(r.URL.Path, "/")[2]
		user, err := pg.GetUser(username)
		if err != nil {
			logger.Errorf("error getting user: %v\n", err)
			if _, err := w.Write([]byte("error fetching user: %v\n")); err != nil {
				logger.Errorf("Error writing error %v\n", err)
			}
			return
		}
		data, err := json.Marshal(user)
		if err != nil {
			logger.Errorf("error marshalling user: %v\n", err)
			return
		}
		io.WriteString(w, string(data))
	})

	mux.HandleFunc("/user", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "PUT" {
			w.Write([]byte("wrong method"))
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}

		body, err := io.ReadAll(r.Body)
		if err != nil {
			logger.Errorf("Error reading body")
			return
		}

		var user postgres.User
		if err := json.Unmarshal(body, &user); err != nil {
			logger.Errorf("Error formatting body into user: %v\n", err)
			return
		}

		logger.Infof("user: %v\n", user)

		user.ID = uuid.New()
		if err := pg.CreateUser(&user); err != nil {
			if err.Error() == "duplicate username" {
				w.WriteHeader(http.StatusOK)
				w.Write([]byte("{\"status\": \"error\", \"error\": \"duplicate username\"}"))
				return
			}
			logger.Errorf("Error creating user in db: %v\n", err)
			return
		}

		w.WriteHeader(http.StatusCreated)
		w.Write([]byte("{\"status\": \"success\"}"))
		return
	})

	mux.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			logger.Errorf("Invalid Method!")
			return
		}

		body, err := io.ReadAll(r.Body)
		if err != nil {
			logger.Errorf("Error reading body")
			return
		}

		var user postgres.User
		if err := json.Unmarshal(body, &user); err != nil {
			logger.Errorf("Error formatting body into user: %v\n", err)
			return
		}

		var jsonUser postgres.User
		if err := json.Unmarshal(body, &jsonUser); err != nil {
			logger.Errorf("Error formatting body into user: %v\n", err)
			return
		}

		pgUser, err := pg.GetUser(user.Username)
		if err != nil {
			logger.Errorf("Error fetching user: %v\n", err)
			w.WriteHeader(http.StatusUnauthorized)
			w.Write([]byte("{\"status\": \"invalid username\"}"))
			return
		}

		if err := bcrypt.CompareHashAndPassword([]byte(pgUser.Password), []byte(jsonUser.Password)); err != nil {
			logger.Error("hash and pass differ")
			w.WriteHeader(http.StatusUnauthorized)
			w.Write([]byte("{\"status\": \"invalid password\"}"))
			return
		}

		session := &postgres.Session{
			ID:     uuid.New(),
			UserID: pgUser.ID,
			Expiry: time.Now().Add(time.Minute * 15).UTC(),
		}
		if err := pg.CreateSession(session); err != nil {
			logger.Errorf("Error creating session: %v\n", err)
			return
		}

		w.Write([]byte("{\"status\": \"success\"}"))
	})
}

func NewServer(logger *logrus.Logger, config *Config) http.Handler {
	mux := http.NewServeMux()
	var handler http.Handler = mux

	pg := postgres.New(logger)

	addRoutes(mux, logger, pg)
	handler = addMiddleware(handler, logger)
	return handler
}

var startCmd = &cobra.Command{
	Use:   "start",
	Short: "start the server with default settings",
	Run: func(cmd *cobra.Command, args []string) {
		// read flags / config files / env vars to determine details of the server
		logger := logrus.New()
		config := &Config{
			Port: "8080",
			Host: "localhost",
		}
		srv := NewServer(logger, config)
		httpServer := &http.Server{
			Addr:    net.JoinHostPort(config.Host, config.Port),
			Handler: srv,
		}

		go func() {
			logger.Logf(logrus.InfoLevel, "listening on %s\n", httpServer.Addr)
			if err := httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				fmt.Fprintf(os.Stderr, "error listening and serving: %s\n", err)
			}
		}()

		ctx := context.Background()

		var wg sync.WaitGroup
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-ctx.Done()
			shutdownCtx := context.Background()
			shutdownCtx, cancel := context.WithTimeout(shutdownCtx, 10*time.Second)
			defer cancel()
			if err := httpServer.Shutdown(shutdownCtx); err != nil {
				fmt.Fprintf(os.Stderr, "error shutting down http server: %s\n", err)
			}
		}()
		wg.Wait()
	},
}

func init() {
	rootCmd.AddCommand(startCmd)
}
