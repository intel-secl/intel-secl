/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package constants

import "time"

// general KBS constants
const (
	ServiceName         = "KBS"
	ExplicitServiceName = "Key Broker Service"
	ServiceDir          = "kbs/"
	ApiVersion          = "/v1"
	ServiceUserName     = "kbs"

	HomeDir      = "/opt/" + ServiceDir
	RunDirPath   = "/run/" + ServiceDir
	ExecLinkPath = "/usr/bin/" + ServiceUserName
	LogDir       = "/var/log/" + ServiceDir
	ConfigDir    = "/etc/" + ServiceDir
	ConfigFile   = "config"

	KeysDir               = HomeDir + "keys/"
	KeysTransferPolicyDir = HomeDir + "keys-transfer-policy/"

	// certificates' path
	TrustedJWTSigningCertsDir = ConfigDir + "certs/trustedjwt/"
	ApsJWTSigningCertsDir     = ConfigDir + "certs/apsjwt/"
	TrustedCaCertsDir         = ConfigDir + "certs/trustedca/"
	SamlCertsDir              = ConfigDir + "certs/saml/"
	TpmIdentityCertsDir       = ConfigDir + "certs/tpm-identity/"

	// defaults
	DefaultKeyManager         = "Kmip"
	DefaultEndpointUrl        = "http://localhost"
	DefaultTransferPolicy     = "urn:intel:trustedcomputing:key-transfer-policy:require-trust-or-authorization"
	DefaultConfigFilePath     = ConfigDir + "config.yml"
	DefaultTransferPolicyFile = ConfigDir + "default_transfer_policy"

	// default locations for tls certificate and key
	DefaultTLSCertPath = ConfigDir + "tls-cert.pem"
	DefaultTLSKeyPath  = ConfigDir + "tls.key"

	// service remove command
	ServiceRemoveCmd = "systemctl disable kbs"

	// tls constants
	DefaultKbsTlsCn     = "KBS TLS Certificate"
	DefaultKbsTlsSan    = "127.0.0.1,localhost"
	DefaultKeyAlgorithm = "rsa"
	DefaultKeyLength    = 3072

	// jwt constants
	JWTCertsCacheTime = "1m"

	// log constants
	DefaultLogLevel     = "info"
	DefaultLogMaxlength = 1500

	// server constants
	DefaultReadTimeout       = 30 * time.Second
	DefaultReadHeaderTimeout = 10 * time.Second
	DefaultWriteTimeout      = 30 * time.Second
	DefaultIdleTimeout       = 10 * time.Second
	DefaultMaxHeaderBytes    = 1 << 20
	DefaultKBSListenerPort   = 9443

	// keymanager constants
	KmipKeyManager = "kmip"

	// algorithm constants
	CRYPTOALG_AES = "AES"
	CRYPTOALG_RSA = "RSA"
	CRYPTOALG_EC  = "EC"

	// kmip constants
	KMIP_1_4 = "1.4"
	KMIP_2_0 = "2.0"

	AttestationTypeKey = "attestation_type"
	AttestationTypeSGX = "SGX"
	AttestationTypeTDX = "TDX"
	TCBStatusUpToDate  = "OK"
)
