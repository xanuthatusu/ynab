package postgres

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/sirupsen/logrus"
	"golang.org/x/crypto/bcrypt"
)

type Postgres struct {
	logger *logrus.Logger
	conn   *pgx.Conn
}

type User struct {
	ID       uuid.UUID `json:"id"`
	Username string    `json:"username"`
	Display  string    `json:"display"`
	Password string    `json:"password"`
}

type Session struct {
	ID     uuid.UUID `json:"session_id"`
	UserID uuid.UUID `json:"user_id"`
	Expiry time.Time `json:"expiry"`
}

func New(logger *logrus.Logger) *Postgres {
	conn, err := pgx.Connect(context.Background(), "postgres://postgres:postgres@localhost:5432/postgres")
	if err != nil {
		logger.Errorf("Unable to connect to postgres: %v\n", err)
	}
	return &Postgres{logger, conn}
}

func (p *Postgres) Close() {
	p.conn.Close(context.Background())
}

func (p *Postgres) GetUser(username string) (*User, error) {
	rows, err := p.conn.Query(context.Background(), "SELECT user_id, display, username, password FROM users WHERE username=$1", username)
	if err != nil {
		p.logger.Errorf("Error fetching users: %v\n", err)
		return nil, err
	}

	users, err := pgx.CollectRows(rows, pgx.RowToStructByName[User])
	if err != nil {
		p.logger.Errorf("Error collecting users: %v\n", err)
		return nil, err
	}

	if len(users) == 0 || len(users) >= 2 {
		err = errors.New(fmt.Sprintf("users array is the wrong length! %d\n", len(users)))
		p.logger.Error(err)
		return nil, err
	}

	return &users[0], nil
}

type emptyStruct struct{}

func (p *Postgres) CreateUser(user *User) error {
	hash, err := bcrypt.GenerateFromPassword([]byte(user.Password), bcrypt.MinCost)
	if err != nil {
		p.logger.Errorf("Error generating hash: %v\n", err)
		return err
	}

	p.logger.Infof("user id: %v\n", user.ID)

	rows, err := p.conn.Query(context.Background(), "INSERT INTO users (id, username, password, display) VALUES ($1, $2, $3, $4)", user.ID, user.Username, string(hash), user.Display)
	if err != nil {
		p.logger.Errorf("Error creating new user %v\n", err)
		return err
	}

	_, err = pgx.CollectOneRow(rows, pgx.RowTo[emptyStruct])
	if err != nil {
		if strings.Contains(err.Error(), "ERROR: duplicate key value violates unique constraint") {
			return errors.New("duplicate username")
		}
	}

	return nil
}

func (p *Postgres) CreateSession(session *Session) error {
	_, err := p.conn.Query(context.Background(), "INSERT INTO sessions (id, user_id, expiry) VALUES ($1, $2, $3)", session.ID, session.UserID, session.Expiry)
	if err != nil {
		return err
	}

	return nil
}
