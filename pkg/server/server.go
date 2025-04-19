package server

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
	"github.com/xanuthatusu/ynab/pkg/postgres"
	"golang.org/x/crypto/bcrypt"
)

type Config struct {
	Port    string
	Address string
}

func addRoutes(
	mux *http.ServeMux,
	logger *logrus.Logger,
	pg *postgres.Postgres,
) {
	mux.HandleFunc("/user/{username}", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" {
			fmt.Fprintf(w, "wrong method")
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}

		username := strings.Split(r.URL.Path, "/")[2]
		user, err := pg.GetUser(username)
		if err != nil {
			logger.Errorf("error getting user: %v\n", err)
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
			w.WriteHeader(http.StatusMethodNotAllowed)
			fmt.Fprintf(w, `{"status": "wrong method"}`)
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
				fmt.Fprintf(w, `{"status": "error", "error": "duplicate username"}`)
				return
			}
			logger.Errorf("Error creating user in db: %v\n", err)
			return
		}

		w.WriteHeader(http.StatusCreated)
		fmt.Fprintf(w, `{"status": "success"}`)
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
			fmt.Fprintf(w, `{"status": "invalid username"}`)
			return
		}

		if err := bcrypt.CompareHashAndPassword([]byte(pgUser.Password), []byte(jsonUser.Password)); err != nil {
			logger.Error("hash and pass differ")
			w.WriteHeader(http.StatusUnauthorized)
			fmt.Fprintf(w, `{"status": "invalid password"}`)
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

		fmt.Fprintf(w, `{"status": "success", "session": "%s"}`, session.ID)
	})

	mux.HandleFunc("/budget", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			logger.Errorf("Invalid Method!")
			w.WriteHeader(http.StatusBadRequest)
			fmt.Fprintf(w, `{"status": "invalid method"}`)
			return
		}

		authHeader := r.Header.Values("Authorization")
		if len(authHeader) <= 0 {
			logger.Errorf("Could not find auth token")
			w.WriteHeader(http.StatusUnauthorized)
			fmt.Fprintf(w, `{"status": "could not find auth token"}`)
			return
		}

		sessionID := strings.Split(authHeader[0], " ")[1]

		if !pg.SessionIsValid(sessionID) {
			if _, err := pg.CleanSessions(); err != nil {
				logger.Errorf("error cleaning sessions: %v\n", err)
			}

			logger.Error("Session is not valid!")
			w.WriteHeader(http.StatusUnauthorized)
			fmt.Fprintf(w, `{"status": "unauthorized"}`)
			return
		}

		w.WriteHeader(http.StatusNotImplemented)
		fmt.Fprintf(w, `{"status": "unimplemented"}`)
		return
	})
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

func New(logger *logrus.Logger, config *Config) http.Handler {
	mux := http.NewServeMux()
	var handler http.Handler = mux

	pg := postgres.New(logger)

	addRoutes(mux, logger, pg)
	handler = addMiddleware(handler, logger)
	return handler
}
