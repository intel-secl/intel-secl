/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package tasks

import (
	"fmt"
	"io"
	"net/url"
	"strings"

	"github.com/intel-secl/intel-secl/v5/pkg/clients/fds"
	"github.com/intel-secl/intel-secl/v5/pkg/clients/vs"
	"github.com/intel-secl/intel-secl/v5/pkg/ihub/config"
	"github.com/intel-secl/intel-secl/v5/pkg/lib/common/setup"
	"github.com/spf13/viper"

	"github.com/pkg/errors"
)

// AttestationServiceConnection is a setup task for setting up the connection to the Host Verification Service (Attestation Service)
type AttestationServiceConnection struct {
	AttestationConfig *config.AttestationConfig
	ConsoleWriter     io.Writer
}

// Run will run the Attestation Service Connection setup task, but will skip if Validate() returns no errors
func (attestationService AttestationServiceConnection) Run() error {
	fmt.Fprintln(attestationService.ConsoleWriter, "Setting up Attestation Service Connection...")

	HvsUrl := viper.GetString(config.HvsBaseUrl)

	if HvsUrl == "" {
		return errors.New("tasks/attestation_service_connection:Run() Missing HVS endpoint url in environment")
	}

	if HvsUrl != "" && !strings.HasSuffix(HvsUrl, "/") {
		HvsUrl = HvsUrl + "/"
		if _, err := url.Parse(HvsUrl); err != nil {
			return errors.Wrap(err, "tasks/attestation_service_connection:Run() HVS URL is invalid")
		}
	}

	attestationService.AttestationConfig.HVSBaseURL = HvsUrl

	return nil
}

// Validate checks whether or not the Attestation Service Connection setup task was completed successfully
func (attestationService AttestationServiceConnection) Validate() error {

	if attestationService.AttestationConfig.HVSBaseURL == "" {
		return errors.New("tasks/attestation_service_connection:Validate() Attestation service Connection: HVS url is not set")
	}

	//validating the service url
	return attestationService.validateService()
}

//validateService Validates the attestation service connection is successful or not by hitting the service url's
func (attestationService AttestationServiceConnection) validateService() error {

	if attestationService.AttestationConfig.HVSBaseURL != "" {
		baseURL, err := url.Parse(attestationService.AttestationConfig.HVSBaseURL)
		if err != nil {
			return errors.Wrap(err, "tasks/attestation_service_connection:validateService() Error in parsing Host Verification service URL")
		}

		vsClient := &vs.Client{
			BaseURL: baseURL,
		}

		_, err = vsClient.GetCaCerts("saml")
		if err != nil {
			return errors.Wrap(err, "tasks/attestation_service_connection:validateService() Error while getting response from Host Verification Service")
		}
	}
	if attestationService.AttestationConfig.FDSBaseURL != "" {
		fdsbaseUrl, err := url.Parse(attestationService.AttestationConfig.FDSBaseURL)
		if err != nil {
			return errors.Wrap(err, "tasks/attestation_service_connection:validateService() Invalid FDS URL "+
				"provided in configuration/env")
		}
		fdsClient := fds.NewClient(fdsbaseUrl, nil, nil,
			"", "")

		_, err = fdsClient.GetVersion()
		if err != nil {
			return errors.Wrap(err, "tasks/attestation_service_connection:validateService() Error while getting"+
				" response from FDS")
		}
	}

	fmt.Fprintln(attestationService.ConsoleWriter, "Attestation Service Connection is successful")
	return nil
}

//PrintHelp Prints the help message
func (attestationService AttestationServiceConnection) PrintHelp(w io.Writer) {
	var envHelp = map[string]string{
		"HVS_BASE_URL": "Base URL for the Host Verification Service",
	}
	setup.PrintEnvHelp(w, "Following environment variables are required for attestation-service-connection setup:", "", envHelp)
	fmt.Fprintln(w, "")
}

func (attestationService AttestationServiceConnection) SetName(n, e string) {}
