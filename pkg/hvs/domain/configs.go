/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */

package domain

import (
	lru "github.com/hashicorp/golang-lru"
	"github.com/intel-secl/intel-secl/v5/pkg/lib/common/crypt"
	"github.com/intel-secl/intel-secl/v5/pkg/lib/host-connector"
	"github.com/intel-secl/intel-secl/v5/pkg/lib/saml"
	"github.com/intel-secl/intel-secl/v5/pkg/lib/verifier"
)

type HostTrustVerifierConfig struct {
	FlavorStore                     FlavorStore
	FlavorGroupStore                FlavorGroupStore
	HostStore                       HostStore
	ReportStore                     ReportStore
	FlavorVerifier                  verifier.Verifier
	CertsStore                      crypt.CertificatesStore
	SamlIssuerConfig                saml.IssuerConfiguration
	SkipFlavorSignatureVerification bool
	HostTrustCache                  *lru.Cache
}

type HostTrustMgrConfig struct {
	PersistStore      QueueStore
	HostStore         HostStore
	HostStatusStore   HostStatusStore
	HostFetcher       HostDataFetcher
	Verifiers         int
	HostTrustVerifier HostTrustVerifier
}

type HostDataFetcherConfig struct {
	HostConnectorProvider host_connector.HostConnectorProvider
	HostConnectionConfig  HostConnectionConfig
	RetryTimeMinutes      int
	HostStatusStore       HostStatusStore
	HostStore             HostStore
	FlavorGroupStore      FlavorGroupStore
	FlavorStore           FlavorStore
	HostTrustCache        *lru.Cache
}

type HostControllerConfig struct {
	HostConnectorProvider          host_connector.HostConnectorProvider
	DataEncryptionKey              []byte
	Username                       string
	Password                       string
	VerifyQuoteForHostRegistration bool
}

type TagCertControllerConfig struct {
	AASApiUrl       string
	ServiceUsername string
	ServicePassword string
}

type HostConnectionConfig struct {
	HCStore         HostCredentialStore
	ServiceUsername string
	ServicePassword string
}
