/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package kbs

import (
	"time"

	"github.com/google/uuid"
)

// KeyTransferPolicy - used in key transfer policy create request and response.
type KeyTransferPolicy struct {
	// swagger:strfmt uuid
	ID              uuid.UUID  `json:"id,omitempty"`
	CreatedAt       time.Time  `json:"created_at,omitempty"`
	AttestationType []string   `json:"attestation_type"`
	TDX             *TdxPolicy `json:"tdx,omitempty"`
	SGX             *SgxPolicy `json:"sgx,omitempty"`
}

type TdxPolicy struct {
	Attributes *TdxAttributes `json:"attributes,omitempty"`
	// swagger:strfmt uuid
	PolicyIds []uuid.UUID `json:"policy_ids,omitempty"`
}

type TdxAttributes struct {
	MrSignerSeam       []string `json:"mrsignerseam,omitempty"`
	MrSeam             []string `json:"mrseam,omitempty"`
	SeamSvn            *uint8   `json:"seamsvn,omitempty"`
	MRTD               []string `json:"mrtd,omitempty"`
	RTMR0              string   `json:"rtmr0,omitempty"`
	RTMR1              string   `json:"rtmr1,omitempty"`
	RTMR2              string   `json:"rtmr2,omitempty"`
	RTMR3              string   `json:"rtmr3,omitempty"`
	EnforceTCBUptoDate *bool    `json:"enforce_tcb_upto_date,omitempty"`
}

type SgxPolicy struct {
	Attributes *SgxAttributes `json:"attributes,omitempty"`
	// swagger:strfmt uuid
	PolicyIds []uuid.UUID `json:"policy_ids,omitempty"`
}

type SgxAttributes struct {
	MrSigner           []string `json:"mrsigner,omitempty"`
	IsvProductId       []uint16 `json:"isvprodid,omitempty"`
	MrEnclave          []string `json:"mrenclave,omitempty"`
	IsvSvn             *uint16  `json:"isvsvn,omitempty"`
	ClientPermissions  []string `json:"client_permissions,omitempty"`
	EnforceTCBUptoDate *bool    `json:"enforce_tcb_upto_date,omitempty"`
}
