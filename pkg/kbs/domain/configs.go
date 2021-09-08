/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package domain

import "github.com/google/uuid"

type KeyControllerConfig struct {
	ApsJwtSigningCertsDir   string
	SamlCertsDir            string
	TrustedCaCertsDir       string
	TpmIdentityCertsDir     string
	DefaultTransferPolicyId uuid.UUID
}
