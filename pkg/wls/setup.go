/*
 * Copyright (C) 2021 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package wls

import (
	"crypto/x509/pkix"
	"fmt"
	"os"
	"strings"

	commConfig "github.com/intel-secl/intel-secl/v5/pkg/lib/common/config"
	cos "github.com/intel-secl/intel-secl/v5/pkg/lib/common/os"
	"github.com/intel-secl/intel-secl/v5/pkg/lib/common/setup"
	"github.com/intel-secl/intel-secl/v5/pkg/wls/config"
	"github.com/intel-secl/intel-secl/v5/pkg/wls/constants"
	"github.com/intel-secl/intel-secl/v5/pkg/wls/tasks"
	"github.com/pkg/errors"
	"github.com/spf13/viper"
)

// input string slice should start with setup
func (a *App) setup(args []string) error {
	if len(args) < 2 {
		return errors.New("Invalid usage of setup")
	}
	// look for cli flags
	var ansFile string
	var force bool
	for i, s := range args {
		if s == "-f" || s == "--file" {
			if i+1 < len(args) {
				ansFile = args[i+1]
			} else {
				return errors.New("Invalid answer file name")
			}
		} else if s == "--force" {
			force = true
		}
	}
	// dump answer file to env
	if ansFile != "" {
		err := setup.ReadAnswerFileToEnv(ansFile)
		if err != nil {
			return errors.Wrap(err, "Failed to read answer file")
		}
	}
	runner, err := a.setupTaskRunner()
	if err != nil {
		return err
	}
	cmd := args[1]
	// print help and return if applicable
	if len(args) > 2 && args[2] == "--help" {
		if cmd == "all" {
			err = runner.PrintAllHelp()
			if err != nil {
				return errors.Wrap(err, "Failed to write to console")
			}
		} else {
			err = runner.PrintHelp(cmd)
			if err != nil {
				return errors.Wrap(err, "Failed to write to console")
			}
		}
		return nil
	}
	if cmd == "all" {
		if err = runner.RunAll(force); err != nil {
			errCmds := runner.FailedCommands()
			fmt.Fprintln(a.errorWriter(), "Error(s) encountered when running all setup commands:")
			for errCmd, failErr := range errCmds {
				fmt.Fprintln(a.errorWriter(), errCmd+": "+failErr.Error())
				err = runner.PrintHelp(errCmd)
				if err != nil {
					return errors.Wrap(err, "Failed to write to console")
				}
			}
			return errors.New("Failed to run all tasks")
		}
		fmt.Fprintln(a.consoleWriter(), "All setup tasks succeeded")
	} else {
		if err = runner.Run(cmd, force); err != nil {
			fmt.Fprintln(a.errorWriter(), cmd+": "+err.Error())
			err = runner.PrintHelp(cmd)
			if err != nil {
				return errors.Wrap(err, "Failed to write to console")
			}
			return errors.New("Failed to run setup task " + cmd)
		}
	}

	err = a.Config.Save(constants.DefaultConfigFilePath)
	if err != nil {
		return errors.Wrap(err, "Failed to save configuration")
	}
	// Containers are always run as non root users, does not require changing ownership of config directories
	if _, err := os.Stat("/.container-env"); err == nil {
		return nil
	}

	return cos.ChownDirForUser(constants.ServiceUserName, a.configDir())
}

// a helper function for setting up the task runner
func (a *App) setupTaskRunner() (*setup.Runner, error) {

	loadAlias()
	viper.SetEnvKeyReplacer(strings.NewReplacer(".", "_", "-", "_"))
	viper.AutomaticEnv()

	if a.configuration() == nil {
		a.Config = defaultConfig()
	}

	runner := setup.NewRunner()
	runner.ConsoleWriter = a.consoleWriter()
	runner.ErrorWriter = a.errorWriter()

	runner.AddTask("download-ca-cert", "", &setup.DownloadCMSCert{
		CaCertDirPath: constants.TrustedCaCertsDir,
		ConsoleWriter: a.consoleWriter(),
		CmsBaseURL:    viper.GetString(commConfig.CmsBaseUrl),
		TlsCertDigest: viper.GetString(commConfig.CmsTlsCertSha384),
	})
	runner.AddTask("download-cert-tls", "tls", &setup.DownloadCert{
		KeyFile:      viper.GetString(commConfig.TlsKeyFile),
		CertFile:     viper.GetString(commConfig.TlsCertFile),
		KeyAlgorithm: constants.DefaultKeyAlgorithm,
		KeyLength:    constants.DefaultKeyLength,
		Subject: pkix.Name{
			CommonName: viper.GetString(commConfig.TlsCommonName),
		},
		SanList:       viper.GetString(commConfig.TlsSanList),
		CertType:      "tls",
		CaCertDirPath: constants.TrustedCaCertsDir,
		ConsoleWriter: a.consoleWriter(),
		CmsBaseURL:    viper.GetString(commConfig.CmsBaseUrl),
		BearerToken:   viper.GetString(commConfig.BearerToken),
	})
	runner.AddTask("update-service-config", "", &tasks.UpdateServiceConfig{
		ServiceConfig: commConfig.ServiceConfig{
			Username: viper.GetString(config.WlsServiceUsername),
			Password: viper.GetString(config.WlsServicePassword),
		},
		AASApiUrl: viper.GetString(commConfig.AasBaseUrl),
		HVSApiUrl: viper.GetString(config.HvsBaseUrl),
		ServerConfig: commConfig.ServerConfig{
			Port:              viper.GetInt(commConfig.ServerPort),
			ReadTimeout:       viper.GetDuration(commConfig.ServerReadTimeout),
			ReadHeaderTimeout: viper.GetDuration(commConfig.ServerReadHeaderTimeout),
			WriteTimeout:      viper.GetDuration(commConfig.ServerWriteTimeout),
			IdleTimeout:       viper.GetDuration(commConfig.ServerIdleTimeout),
			MaxHeaderBytes:    viper.GetInt(commConfig.ServerMaxHeaderBytes),
		},
		DefaultPort:   constants.DefaultWLSListenerPort,
		AppConfig:     &a.Config,
		ConsoleWriter: a.consoleWriter(),
	})
	runner.AddTask("download-saml-ca-cert", "", &tasks.DownloadSamlCaCert{
		HvsApiUrl:         viper.GetString(config.HvsBaseUrl),
		ConsoleWriter:     a.consoleWriter(),
		SamlCertPath:      constants.SamlCaCertFilePath,
		TrustedCaCertsDir: constants.TrustedCaCertsDir,
	})
	return runner, nil
}
