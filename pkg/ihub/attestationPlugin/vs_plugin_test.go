/*
 * Copyright (C) 2022 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */

package attestationPlugin

import (
	"encoding/xml"
	"io/ioutil"
	"reflect"
	"testing"

	"github.com/intel-secl/intel-secl/v5/pkg/ihub/constants"

	"github.com/intel-secl/intel-secl/v5/pkg/clients/vs"
	"github.com/intel-secl/intel-secl/v5/pkg/ihub/config"
	testutility "github.com/intel-secl/intel-secl/v5/pkg/ihub/test"
	commConfig "github.com/intel-secl/intel-secl/v5/pkg/lib/common/config"
	"github.com/intel-secl/intel-secl/v5/pkg/lib/saml"
)

var sampleSamlCertPath = testutility.SampleSamlCertPath
var sampleRootCertDirPath = "../test/resources/trustedCACert"
var sampleSamlReportPath = "../test/resources/saml_report.xml"

func TestGetHostReports(t *testing.T) {

	server := testutility.MockServer(t)
	defer server.Close()

	c := testutility.SetupMockK8sConfiguration(t, server.URL)
	report, err := ioutil.ReadFile(sampleSamlReportPath)
	if err != nil {
		t.Log("attestationPlugin/vs_plugin_test:TestGetHostReports() : Unable to read file")
	}

	samlReport := &saml.Saml{}
	err = xml.Unmarshal(report, samlReport)

	type args struct {
		h string
		c *config.Configuration
	}
	tests := []struct {
		name string
		args args
		want *saml.Saml
	}{
		{
			name: "TestGetHostReports Test 1",
			args: args{
				c: c,
			},
			want: samlReport,
		},
		{
			name: "TestGetHostReports Test 2",
			args: args{
				c: &config.Configuration{
					AASBaseUrl: server.URL + "/aas",
					AttestationService: config.AttestationConfig{
						HVSBaseURL: "hvs/v2"},
					Endpoint: config.Endpoint{
						Type: constants.K8sTenant,
					},
				},
			},

			want: nil,
		},
		{
			name: "TestGetHostReports Test 3",
			args: args{
				c: &config.Configuration{
					AASBaseUrl: server.URL + "/aas",
					AttestationService: config.AttestationConfig{
						HVSBaseURL: "hvs/v2"},
					Endpoint: config.Endpoint{
						Type: "",
					},
				},
			},

			want: nil,
		},
		{
			name: "TestGetHostReports Test 4",
			args: args{
				c: &config.Configuration{},
			},

			want: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tArgs := tt.args
			// TODO need to create a mock saml report verifier since we already have the saml report verifier test
			// or we need to move all resources like saml cert, saml report to common folder
			got, _ := GetHostReports(tArgs.h, tArgs.c, sampleRootCertDirPath, sampleSamlCertPath)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("attestationPlugin/vs_plugin_test:TestGetHostReports()  got = %v, want: %v", got != nil, tt.want != nil)
			}
		})
	}
}

func TestGetCaCerts(t *testing.T) {
	samlCert, err := ioutil.ReadFile(sampleSamlCertPath)
	samlCertificate := string(samlCert)
	if err != nil {
		t.Log("attestationPlugin/vs_plugin_test:TestGetCaCerts() : Unable to read file")
	}

	server := testutility.MockServer(t)
	defer server.Close()

	type args struct {
		domain        string
		configuration *config.Configuration
	}
	tests := []struct {
		name string
		args args
		want []byte
	}{
		{
			name: "Validate CA certificate for SAML 1",
			args: args{
				domain: "SAML",
				configuration: &config.Configuration{
					AASBaseUrl: server.URL + "/aas/v1",
					IHUB: commConfig.ServiceConfig{
						Username: "test@user",
						Password: "test@password",
					},
					AttestationService: config.AttestationConfig{
						HVSBaseURL: "",
					},
				},
			},
			want: nil,
		},

		{
			name: "Validate CA certificate for SAML 2",
			args: args{
				domain: "SAML",
				configuration: &config.Configuration{
					AASBaseUrl: server.URL + "/aas/v1",
					IHUB: commConfig.ServiceConfig{
						Username: "test@user",
						Password: "test@password",
					},
					AttestationService: config.AttestationConfig{
						HVSBaseURL: server.URL + "/hvs/v2/",
					},
				},
			},
			want: []byte(samlCertificate),
		},
	}

	for _, tt := range tests {
		VsClient = &vs.Client{}
		t.Run(tt.name, func(t *testing.T) {
			tArgs := tt.args

			got1, _ := GetCaCerts(tArgs.domain, tArgs.configuration, "")

			if !reflect.DeepEqual(got1, tt.want) {
				t.Errorf("attestationPlugin/vs_plugin_test:TestGetCaCerts() got1 = %v, want1: %v", got1, tt.want)
			}
		})
	}
}

func Test_initializeCert(t *testing.T) {

	type args struct {
		certDirectory string
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			name: "Test_initializeCert Test 1",
			args: args{
				certDirectory: "",
			},
			wantErr: true,
		},
		{
			name: "Test_initializeCert Test 2",
			args: args{
				certDirectory: "../test/resources/",
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := loadCertificates(tt.args.certDirectory); (err != nil) != tt.wantErr {
				t.Errorf("attestation_plugin/vs_plugin_test:loadCertificates() Error in initializing cert :error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func Test_initializeClient(t *testing.T) {
	server := testutility.MockServer(t)
	defer server.Close()

	type args struct {
		con           *config.Configuration
		certDirectory string
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			name: "ValidTest_initializeClient Test 1",
			args: args{
				certDirectory: "",
				con: &config.Configuration{
					AASBaseUrl: server.URL + "/aas/v1",
					IHUB: commConfig.ServiceConfig{
						Username: "test@user",
						Password: "test@password",
					},
					AttestationService: config.AttestationConfig{
						HVSBaseURL: server.URL + "/hvs/v2",
					},
				},
			},
			wantErr: false,
		},
		{
			name: "InvalidTest_initializeClient Test 1",
			args: args{
				certDirectory: "",
				con: &config.Configuration{
					AASBaseUrl: server.URL + "/aas\v1",
					IHUB: commConfig.ServiceConfig{
						Username: "test@user",
						Password: "test@password",
					},
					AttestationService: config.AttestationConfig{
						HVSBaseURL: server.URL + "/hvs/v2",
					},
				},
			},
			wantErr: true,
		},
		{
			name: "InvalidTest_initializeClient Test 2",
			args: args{
				certDirectory: "",
				con: &config.Configuration{
					AASBaseUrl: server.URL + "/aas/v1",
					IHUB: commConfig.ServiceConfig{
						Username: "test@user",
						Password: "test@password",
					},
					AttestationService: config.AttestationConfig{
						HVSBaseURL: server.URL + "/hvs\v2",
					},
				},
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		VsClient = &vs.Client{}
		t.Run(tt.name, func(t *testing.T) {
			_, err := initializeClient(tt.args.con, tt.args.certDirectory)
			if (err != nil) != tt.wantErr {
				t.Errorf("attestationPlugin/vs_plugin_test:initializeClient() Error in initializing client :error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
