package cmd

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/xanuthatusu/ynab/pkg/server"
)

var startCmd = &cobra.Command{
	Use:   "start",
	Short: "start the server with default settings",
	Run: func(cmd *cobra.Command, args []string) {
		// read flags / config files / env vars to determine details of the server
		logger := logrus.New()
		config := &server.Config{
			Port:    "8080",
			Address: "localhost",
		}
		srv := server.New(logger, config)
		httpServer := &http.Server{
			Addr:    net.JoinHostPort(config.Address, config.Port),
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
