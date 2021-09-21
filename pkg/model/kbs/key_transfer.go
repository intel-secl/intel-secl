/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */

package kbs

import "github.com/google/uuid"

type KeyTransferRequest struct {
	Quote            string `json:"quote,omitempty"`
	AttestationToken string `json:"attestation_token,omitempty"`
	UserData         string `json:"user_data"`
}

type KeyTransferResponse struct {
	WrappedKey string `json:"wrapped_key"`
	WrappedSWK string `json:"wrapped_swk,omitempty"`
}

type AttestationTokenClaim struct {
	MrSeam          string      `json:"mrseam,omitempty"`
	MrEnclave       string      `json:"mrenclave,omitempty"`
	MrSigner        string      `json:"mrsigner,omitempty"`
	MrSignerSeam    string      `json:"mrsignerseam,omitempty"`
	IsvProductId    uint16      `json:"isvprodid,omitempty"`
	MRTD            string      `json:"mrtd,omitempty"`
	RTMR0           string      `json:"rtmr0,omitempty"`
	RTMR1           string      `json:"rtmr1,omitempty"`
	RTMR2           string      `json:"rtmr2,omitempty"`
	RTMR3           string      `json:"rtmr3,omitempty"`
	SeamSvn         uint8       `json:"seamsvn, omitempty"`
	IsvSvn          uint16      `json:"isvsvn,omitempty"`
	EnclaveHeldData string      `json:"enclave_held_data,omitempty"`
	PolicyIds       []uuid.UUID `json:"policy_ids"`
	TcbStatus       string      `json:"tcb_status"`
	Tee             string      `json:"tee"`
	Version         string      `json:"ver"`
}
