/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package ihub

import (
	"fmt"
	"runtime/debug"

	"github.com/intel-secl/intel-secl/v5/pkg/ihub/config"
	"github.com/intel-secl/intel-secl/v5/pkg/ihub/constants"
	"github.com/intel-secl/intel-secl/v5/pkg/lib/common/setup"
	"github.com/sirupsen/logrus"
	"io"
	"os"
	"os/exec"
	"time"

	"github.com/pkg/errors"

	commLog "github.com/intel-secl/intel-secl/v5/pkg/lib/common/log"
	commLogMsg "github.com/intel-secl/intel-secl/v5/pkg/lib/common/log/message"
	commLogInt "github.com/intel-secl/intel-secl/v5/pkg/lib/common/log/setup"
)

var errInvalidCmd = errors.New("Invalid input after command")

type App struct {
	HomeDir        string
	InstanceName   string
	ConfigDir      string
	LogDir         string
	ExecutablePath string
	ExecLinkPath   string
	RunDirPath     string
	Config         *config.Configuration
	ConsoleWriter  io.Writer
	LogWriter      io.Writer
	SecLogWriter   io.Writer
	ErrorWriter    io.Writer
}

func (app *App) Run(args []string) error {
	defer func() {
		if err := recover(); err != nil {
			log.Errorf("Panic occurred: %+v", err)
			log.Error(string(debug.Stack()))
		}
	}()
	if len(args) < 2 {
		err := errors.New("Invalid usage of " + constants.ServiceName)
		app.printUsageWithError(err)
		return err
	}
	cmd := args[1]
	switch cmd {
	case "run":
		if len(args) >= constants.MaxArguments {
			return errInvalidCmd
		}
		if err := app.startDaemon(); err != nil {
			fmt.Fprintln(os.Stderr, "Error: daemon did not start - ", err.Error())
			// wait some time for logs to flush - otherwise, there will be no entry in syslog
			time.Sleep(10 * time.Millisecond)
			return errors.Wrap(err, "Error starting IHUB Service")
		}
	case "help", "-h", "--help":
		app.printUsage()
		return nil
	case "start":
		if len(args) >= constants.MaxArguments {
			return errInvalidCmd
		}
		return app.start()
	case "stop":
		if len(args) >= constants.MaxArguments {
			return errInvalidCmd
		}
		return app.stop()
	case "status":
		if len(args) >= constants.MaxArguments {
			return errInvalidCmd
		}
		return app.status()
	case "uninstall":
		purge := false
		exec := false
		if len(args) >= constants.MaxArguments+2 { //For additional purge and all
			return errInvalidCmd
		}

		for _, flag := range args {
			if flag == "--purge" {
				purge = true
			} else if flag == "--exec" {
				exec = true
			}
		}

		app.uninstall(purge, exec)
		return nil
	case "version", "-v", "--version":
		app.printVersion()
		return nil
	case "setup":
		if err := app.setup(args[1:]); err != nil {
			if errors.Cause(err) == setup.ErrTaskNotFound {
				app.printUsageWithError(err)
			} else {
				fmt.Fprintln(app.errorWriter(), err.Error())
			}
			return err
		}
	default:
		err := errors.New("Unrecognized command: " + cmd)
		app.printUsageWithError(err)
		return err
	}
	return nil
}

func (app *App) consoleWriter() io.Writer {
	if app.ConsoleWriter != nil {
		return app.ConsoleWriter
	}
	return os.Stdout
}

func (app *App) errorWriter() io.Writer {
	if app.ErrorWriter != nil {
		return app.ErrorWriter
	}
	return os.Stderr
}

func (app *App) secLogWriter() io.Writer {
	if app.SecLogWriter != nil {
		return app.SecLogWriter
	}
	return os.Stdout
}

func (app *App) logWriter() io.Writer {
	if app.LogWriter != nil {
		return app.LogWriter
	}
	return os.Stderr
}

func (app *App) configuration() *config.Configuration {
	if app.Config != nil {
		return app.Config
	}
	c, err := config.LoadConfiguration()
	if err == nil {
		app.Config = c
		return app.Config
	}
	return nil
}

func (app *App) configureLogs(isStdOut bool, isFileOut bool) {

	var ioWriterDefault io.Writer
	ioWriterDefault = app.logWriter()
	if isStdOut {
		if isFileOut {
			ioWriterDefault = io.MultiWriter(os.Stdout, app.logWriter())
		} else {
			ioWriterDefault = os.Stdout
		}
	}
	ioWriterSecurity := io.MultiWriter(ioWriterDefault, app.secLogWriter())

	logConfig := app.configuration().Log
	lv, err := logrus.ParseLevel(logConfig.Level)
	if err != nil {
		fmt.Println("Failed to initiate loggers. Invalid log level: " + logConfig.Level)
	}
	f := commLog.LogFormatter{MaxLength: logConfig.MaxLength}
	commLogInt.SetLogger(commLog.DefaultLoggerName, lv, &f, ioWriterDefault, false)
	commLogInt.SetLogger(commLog.SecurityLoggerName, lv, &f, ioWriterSecurity, false)

	secLog.Info(commLogMsg.LogInit)
	log.Info(commLogMsg.LogInit)
}

func (app *App) start() error {
	serviceName := constants.InstancePrefix + app.InstanceName
	fmt.Fprintln(app.consoleWriter(), `Forwarding to "systemctl start `+serviceName+`"`)
	systemctl, err := exec.LookPath("systemctl")
	if err != nil {
		return errors.Wrap(err, "Could not locate systemctl to start service")
	}
	cmd := exec.Command(systemctl, "start", serviceName)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Env = os.Environ()
	return cmd.Run()
}

func (app *App) stop() error {
	serviceName := constants.InstancePrefix + app.InstanceName
	fmt.Fprintln(app.consoleWriter(), `Forwarding to "systemctl stop `+serviceName+`"`)
	systemctl, err := exec.LookPath("systemctl")
	if err != nil {
		return errors.Wrap(err, "Could not locate systemctl to stop service")
	}
	cmd := exec.Command(systemctl, "stop", serviceName)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Env = os.Environ()
	return cmd.Run()
}

func (app *App) status() error {
	serviceName := constants.InstancePrefix + app.InstanceName
	fmt.Fprintln(app.consoleWriter(), `Forwarding to "systemctl status `+serviceName+`"`)
	systemctl, err := exec.LookPath("systemctl")
	if err != nil {
		return errors.Wrap(err, "Could not locate systemctl to check status of service")
	}
	cmd := exec.Command(systemctl, "status", serviceName)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Env = os.Environ()
	return cmd.Run()
}
