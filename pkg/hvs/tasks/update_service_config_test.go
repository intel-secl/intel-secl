/*
 * Copyright (C) 2022 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */

package tasks

import (
	"bytes"
	"crypto/sha1"
	"encoding/hex"
	"io"
	"os"
	"testing"

	"github.com/intel-secl/intel-secl/v5/pkg/hvs/config"
	commConfig "github.com/intel-secl/intel-secl/v5/pkg/lib/common/config"
)

func TestUpdateServiceConfig_Run(t *testing.T) {
	type fields struct {
		ServiceConfig commConfig.ServiceConfig
		AASApiUrl     string
		AppConfig     **config.Configuration
		ServerConfig  commConfig.ServerConfig
		DefaultPort   int
		NatServers    string
		ConsoleWriter io.Writer
	}
	config := &config.Configuration{}
	tests := []struct {
		name    string
		fields  fields
		wantErr bool
	}{
		{
			name: "Valid case - update service config",
			fields: fields{
				ServiceConfig: commConfig.ServiceConfig{
					Username: "Test",
					Password: "Test",
				},
				AASApiUrl:     "Test",
				AppConfig:     &config,
				ServerConfig:  commConfig.ServerConfig{},
				DefaultPort:   1234,
				NatServers:    "Test",
				ConsoleWriter: os.Stdout,
			},
			wantErr: false,
		},
		{
			name: "Username not set",
			fields: fields{
				ServiceConfig: commConfig.ServiceConfig{
					Password: "Test",
				},
				AASApiUrl:     "Test",
				AppConfig:     &config,
				ServerConfig:  commConfig.ServerConfig{},
				DefaultPort:   1234,
				NatServers:    "Test",
				ConsoleWriter: os.Stdout,
			},
			wantErr: true,
		},
		{
			name: "Password not set",
			fields: fields{
				ServiceConfig: commConfig.ServiceConfig{
					Username: "Test",
				},
				AASApiUrl:     "Test",
				AppConfig:     &config,
				ServerConfig:  commConfig.ServerConfig{},
				DefaultPort:   1234,
				NatServers:    "Test",
				ConsoleWriter: os.Stdout,
			},
			wantErr: true,
		},
		{
			name: "AASApiUrl not set",
			fields: fields{
				ServiceConfig: commConfig.ServiceConfig{
					Username: "Test",
					Password: "Test",
				},
				AppConfig:     &config,
				ServerConfig:  commConfig.ServerConfig{},
				DefaultPort:   1234,
				NatServers:    "Test",
				ConsoleWriter: os.Stdout,
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			uc := UpdateServiceConfig{
				ServiceConfig: tt.fields.ServiceConfig,
				AASApiUrl:     tt.fields.AASApiUrl,
				AppConfig:     tt.fields.AppConfig,
				ServerConfig:  tt.fields.ServerConfig,
				DefaultPort:   tt.fields.DefaultPort,
				NatServers:    tt.fields.NatServers,
				ConsoleWriter: tt.fields.ConsoleWriter,
			}
			if err := uc.Run(); (err != nil) != tt.wantErr {
				t.Errorf("UpdateServiceConfig.Run() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestUpdateServiceConfig_SetName(t *testing.T) {
	type fields struct {
		ServiceConfig commConfig.ServiceConfig
		AASApiUrl     string
		AppConfig     **config.Configuration
		ServerConfig  commConfig.ServerConfig
		DefaultPort   int
		NatServers    string
		ConsoleWriter io.Writer
	}
	type args struct {
		n string
		e string
	}
	tests := []struct {
		name   string
		fields fields
		args   args
	}{
		{
			name: "Set name",
			args: args{
				n: "",
				e: "",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			uc := UpdateServiceConfig{}
			uc.SetName(tt.args.n, tt.args.e)
		})
	}
}

func TestUpdateServiceConfig_Validate(t *testing.T) {
	type fields struct {
		ServiceConfig commConfig.ServiceConfig
		AASApiUrl     string
		AppConfig     **config.Configuration
		ServerConfig  commConfig.ServerConfig
		DefaultPort   int
		NatServers    string
		ConsoleWriter io.Writer
	}
	configValid := &config.Configuration{
		HVS: commConfig.ServiceConfig{
			Username: "Test",
			Password: "Test",
		},
		AASApiUrl: "Test",
		Server: commConfig.ServerConfig{
			Port: 1234,
		},
	}
	configWithInvalidUsername := &config.Configuration{
		HVS: commConfig.ServiceConfig{
			Password: "Test",
		},
		AASApiUrl: "Test",
		Server: commConfig.ServerConfig{
			Port: 1234,
		},
	}
	configWithInvalidPassword := &config.Configuration{
		HVS: commConfig.ServiceConfig{
			Username: "Test",
		},
		AASApiUrl: "Test",
		Server: commConfig.ServerConfig{
			Port: 1234,
		},
	}
	configWithInvalidUrl := &config.Configuration{
		HVS: commConfig.ServiceConfig{
			Username: "Test",
			Password: "Test",
		},
		Server: commConfig.ServerConfig{
			Port: 1234,
		},
	}
	configWithInvalidPort := &config.Configuration{
		HVS: commConfig.ServiceConfig{
			Username: "Test",
			Password: "Test",
		},
		AASApiUrl: "Test",
		Server: commConfig.ServerConfig{
			Port: 1023,
		},
	}
	tests := []struct {
		name    string
		fields  fields
		wantErr bool
	}{
		{
			name: "Valid case- validate successfully",
			fields: fields{
				ServiceConfig: commConfig.ServiceConfig{
					Username: "Test",
					Password: "Test",
				},
				AASApiUrl:     "Test",
				AppConfig:     &configValid,
				ServerConfig:  commConfig.ServerConfig{},
				DefaultPort:   1234,
				NatServers:    "Test",
				ConsoleWriter: os.Stdout,
			},
			wantErr: false,
		},
		{
			name: "Username not set",
			fields: fields{
				ServiceConfig: commConfig.ServiceConfig{
					Username: "Test",
					Password: "Test",
				},
				AASApiUrl:     "Test",
				AppConfig:     &configWithInvalidUsername,
				ServerConfig:  commConfig.ServerConfig{},
				DefaultPort:   1234,
				NatServers:    "Test",
				ConsoleWriter: os.Stdout,
			},
			wantErr: true,
		},
		{
			name: "Password not set",
			fields: fields{
				ServiceConfig: commConfig.ServiceConfig{
					Username: "Test",
					Password: "Test",
				},
				AASApiUrl:     "Test",
				AppConfig:     &configWithInvalidPassword,
				ServerConfig:  commConfig.ServerConfig{},
				DefaultPort:   1234,
				NatServers:    "Test",
				ConsoleWriter: os.Stdout,
			},
			wantErr: true,
		},
		{
			name: "AASAPIUrl not set",
			fields: fields{
				ServiceConfig: commConfig.ServiceConfig{
					Username: "Test",
					Password: "Test",
				},
				AASApiUrl:     "Test",
				AppConfig:     &configWithInvalidUrl,
				ServerConfig:  commConfig.ServerConfig{},
				DefaultPort:   1234,
				NatServers:    "Test",
				ConsoleWriter: os.Stdout,
			},
			wantErr: true,
		},
		{
			name: "port not set",
			fields: fields{
				ServiceConfig: commConfig.ServiceConfig{
					Username: "Test",
					Password: "Test",
				},
				AASApiUrl:     "Test",
				AppConfig:     &configWithInvalidPort,
				ServerConfig:  commConfig.ServerConfig{},
				DefaultPort:   1234,
				NatServers:    "Test",
				ConsoleWriter: os.Stdout,
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			uc := UpdateServiceConfig{
				ServiceConfig: tt.fields.ServiceConfig,
				AASApiUrl:     tt.fields.AASApiUrl,
				AppConfig:     tt.fields.AppConfig,
				ServerConfig:  tt.fields.ServerConfig,
				DefaultPort:   tt.fields.DefaultPort,
				NatServers:    tt.fields.NatServers,
				ConsoleWriter: tt.fields.ConsoleWriter,
			}
			if err := uc.Validate(); (err != nil) != tt.wantErr {
				t.Errorf("UpdateServiceConfig.Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestUpdateServiceConfig_PrintHelp(t *testing.T) {
	type fields struct {
		ServiceConfig commConfig.ServiceConfig
		AASApiUrl     string
		AppConfig     **config.Configuration
		ServerConfig  commConfig.ServerConfig
		DefaultPort   int
		NatServers    string
		ConsoleWriter io.Writer
	}
	tests := []struct {
		name   string
		fields fields
		wantW  string
	}{
		{
			name:  " Print help statement",
			wantW: "ca5a1fe5d56aa13bd66e527126daf9d123303f7f",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			uc := UpdateServiceConfig{
				ServiceConfig: tt.fields.ServiceConfig,
				AASApiUrl:     tt.fields.AASApiUrl,
				AppConfig:     tt.fields.AppConfig,
				ServerConfig:  tt.fields.ServerConfig,
				DefaultPort:   tt.fields.DefaultPort,
				NatServers:    tt.fields.NatServers,
				ConsoleWriter: tt.fields.ConsoleWriter,
			}
			w := &bytes.Buffer{}
			uc.PrintHelp(w)
			gotW := w.String()
			h := sha1.New()
			h.Write([]byte(gotW))
			bs := h.Sum(nil)
			if hex.EncodeToString(bs) != tt.wantW {
				t.Errorf("UpdateServiceConfig.PrintHelp() = %v, want %v", gotW, tt.wantW)
			}
		})
	}
}
