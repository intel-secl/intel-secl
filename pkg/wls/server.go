/*
 * Copyright (C) 2021 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package wls

import (
	"context"
	"crypto/tls"
	"fmt"
	"github.com/gorilla/handlers"
	"github.com/intel-secl/intel-secl/v5/pkg/lib/common/crypt"
	commLog "github.com/intel-secl/intel-secl/v5/pkg/lib/common/log"
	commLogMsg "github.com/intel-secl/intel-secl/v5/pkg/lib/common/log/message"
	"github.com/intel-secl/intel-secl/v5/pkg/lib/common/middleware"
	"github.com/intel-secl/intel-secl/v5/pkg/wls/constants"
	wlsModel "github.com/intel-secl/intel-secl/v5/pkg/wls/domain/model"
	"github.com/intel-secl/intel-secl/v5/pkg/wls/router"
	"github.com/pkg/errors"
	stdlog "log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"
)

var defaultLog = commLog.GetDefaultLogger()
var secLog = commLog.GetSecurityLogger()

func (a *App) startServer() error {
	defaultLog.Trace("app:startServer() Entering")
	defer defaultLog.Trace("app:startServer() Leaving")

	c := a.configuration()
	if c == nil {
		return errors.New("Failed to load configuration")
	}
	// initialize log
	if err := a.configureLogs(c.Log.EnableStdout, true); err != nil {
		return err
	}

	certStore, err := crypt.LoadCertificates(a.loadCertPathStore(), wlsModel.GetUniqueCertTypes())
	if err != nil {
		return errors.Wrap(err, "Error while loading required certificates")
	}
	// Initialize routes
	routes, err := router.InitRoutes(c, certStore)
	if err != nil {
		return errors.Wrap(err, "An error occurred while initializing routes")
	}
	loggerMiddleware := middleware.LogWriterMiddleware{a.logWriter()}
	routes.Use(loggerMiddleware.WriteDurationLog())
	defaultLog.Info("Starting server")
	// WLS is a user-facing service, hence keeping support for TLS version v12
	tlsConfig := &tls.Config{
		MinVersion: tls.VersionTLS12,
		CipherSuites: []uint16{tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256},
	}
	// Setup signal handlers to gracefully handle termination
	stop := make(chan os.Signal)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	httpLog := stdlog.New(a.httpLogWriter(), "", 0)
	h := &http.Server{
		Addr:              fmt.Sprintf(":%d", c.Server.Port),
		Handler:           handlers.RecoveryHandler(handlers.RecoveryLogger(httpLog), handlers.PrintRecoveryStack(true))(handlers.CombinedLoggingHandler(a.httpLogWriter(), routes)),
		ErrorLog:          httpLog,
		TLSConfig:         tlsConfig,
		ReadTimeout:       c.Server.ReadTimeout,
		ReadHeaderTimeout: c.Server.ReadHeaderTimeout,
		WriteTimeout:      c.Server.WriteTimeout,
		IdleTimeout:       c.Server.IdleTimeout,
		MaxHeaderBytes:    c.Server.MaxHeaderBytes,
	}

	tlsCert := c.TLS.CertFile
	tlsKey := c.TLS.KeyFile
	// dispatch web server go routine
	go func() {
		if err := h.ListenAndServeTLS(tlsCert, tlsKey); err != nil {
			defaultLog.WithError(err).Info("Failed to start HTTPS server")
			stop <- syscall.SIGTERM
		}
	}()

	secLog.Info(commLogMsg.ServiceStart)
	// TODO dispatch Service status checker goroutine
	<-stop

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := h.Shutdown(ctx); err != nil {
		defaultLog.WithError(err).Info("Failed to gracefully shutdown webserver")
		return err
	}
	secLog.Info(commLogMsg.ServiceStop)
	return nil
}

func (a *App) loadCertPathStore() *crypt.CertificatesPathStore {
	return &crypt.CertificatesPathStore{
		wlsModel.CaCertTypesRootCa.String(): crypt.CertLocation{
			CertPath: constants.TrustedCaCertsDir,
		},
		wlsModel.CertTypesSaml.String(): crypt.CertLocation{
			CertPath: constants.SamlCaCertFilePath,
		},
	}
}
