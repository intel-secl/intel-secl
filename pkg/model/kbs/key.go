/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package kbs

import (
	"time"

	"github.com/google/uuid"
)

// KeyInformation - Contains required key related attributes for key create or register request.
type KeyInformation struct {
	// swagger:strfmt uuid
	ID        uuid.UUID `json:"id,omitempty"`
	Algorithm string    `json:"algorithm"`
	KeyLength int       `json:"key_length,omitempty"`
	CurveType string    `json:"curve_type,omitempty"`
	KeyString string    `json:"key_string,omitempty"`
	KmipKeyID string    `json:"kmip_key_id,omitempty"`
}

// KeyRequest - All required attributes for key create or register request.
type KeyRequest struct {
	KeyInformation *KeyInformation `json:"key_information"`
	// swagger:strfmt uuid
	TransferPolicyID uuid.UUID `json:"transfer_policy_id,omitempty"`
	Label            string    `json:"label,omitempty"`
	Usage            string    `json:"usage,omitempty"`
}

// KeyResponse - key attributes from key create or register response.
type KeyResponse struct {
	KeyInformation *KeyInformation `json:"key_information"`
	// swagger:strfmt uuid
	TransferPolicyID uuid.UUID `json:"transfer_policy_id"`
	TransferLink     string    `json:"transfer_link"`
	CreatedAt        time.Time `json:"created_at"`
	Label            string    `json:"label,omitempty"`
	Usage            string    `json:"usage,omitempty"`
}
