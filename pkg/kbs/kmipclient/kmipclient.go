/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package kmipclient

// //The following CFLAGS require 'export CGO_CFLAGS_ALLOW="-f.*"' in the executable that uses kmip-client (i.e. kbs).
// #cgo CFLAGS: -fno-strict-overflow -fno-delete-null-pointer-checks -fwrapv -fstack-protector-strong
// #cgo LDFLAGS: -lssl -lcrypto -lkmip
// #include <stdlib.h>
// #include "kmipclient.h"
import "C"

import (
	"unsafe"

	"github.com/intel-secl/intel-secl/v3/pkg/kbs/constants"
	"github.com/intel-secl/intel-secl/v3/pkg/lib/common/log"
	"github.com/pkg/errors"
)

var defaultLog = log.GetDefaultLogger()

type kmipClient struct {
}

func NewKmipClient() KmipClient {
	return &kmipClient{}
}

// InitializeClient initializes all the values required for establishing connection to kmip server
func (kc *kmipClient) InitializeClient(serverIP, serverPort, clientCert, clientKey, rootCert string) error {
	defaultLog.Trace("kmipclient/kmipclient:InitializeClient() Entering")
	defer defaultLog.Trace("kmipclient/kmipclient:InitializeClient() Leaving")

	address := C.CString(serverIP)
	defer C.free(unsafe.Pointer(address))

	port := C.CString(serverPort)
	defer C.free(unsafe.Pointer(port))

	certificate := C.CString(clientCert)
	defer C.free(unsafe.Pointer(certificate))

	key := C.CString(clientKey)
	defer C.free(unsafe.Pointer(key))

	ca := C.CString(rootCert)
	defer C.free(unsafe.Pointer(ca))

	result := C.kmipw_init((*C.char)(address), (*C.char)(port), (*C.char)(certificate), (*C.char)(key), (*C.char)(ca))
	if result != constants.KMIP_CLIENT_SUCCESS {
		return errors.New("Failed to initialize kmip client. Check kmipclient logs for more details.")
	}

	defaultLog.Info("kmipclient/kmipclient:InitializeClient() Kmip client initialized")
	return nil
}

// CreateSymmetricKey creates a symmetric key on kmip server
func (kc *kmipClient) CreateSymmetricKey(alg, length int) (string, error) {
	defaultLog.Trace("kmipclient/kmipclient:CreateSymmetricKey() Entering")
	defer defaultLog.Trace("kmipclient/kmipclient:CreateSymmetricKey() Leaving")

	algId := C.int(alg)
	algLength := C.int(length)

	keyID := C.kmipw_create(algId, algLength)
	if keyID == nil {
		return "", errors.New("Failed to create symmetric key on kmip server. Check kmipclient logs for more details.")
	}

	defaultLog.Info("kmipclient/kmipclient:CreateSymmetricKey() Created symmetric key on kmip server")
	kmipId := C.GoString(keyID)
	return kmipId, nil
}

// DeleteSymmetric deletes a symmetric key from kmip server
func (kc *kmipClient) DeleteSymmetricKey(id string) error {
	defaultLog.Trace("kmipclient/kmipclient:DeleteSymmetricKey() Entering")
	defer defaultLog.Trace("kmipclient/kmipclient:DeleteSymmetricKey() Leaving")

	keyId := C.CString(id)
	defer C.free(unsafe.Pointer(keyId))

	result := C.kmipw_destroy(keyId)
	if result != constants.KMIP_CLIENT_SUCCESS {
		return errors.New("Failed to delete symmetric key from kmip server. Check kmipclient logs for more details.")
	}

	defaultLog.Info("kmipclient/kmipclient:DeleteSymmetricKey() Deleted symmetric key from kmip server")
	return nil
}

// GetSymmetricKey retrieves a symmetric key from kmip server
func (kc *kmipClient) GetSymmetricKey(id string) ([]byte, error) {
	defaultLog.Trace("kmipclient/kmipclient:GetSymmetricKey() Entering")
	defer defaultLog.Trace("kmipclient/kmipclient:GetSymmetricKey() Leaving")

	keyID := C.CString(id)
	defer C.free(unsafe.Pointer(keyID))

	keyBuffer := C.malloc(32)
	defer C.free(unsafe.Pointer(keyBuffer))

	result := C.kmipw_get((*C.char)(keyID), (*C.char)(keyBuffer))
	if result != constants.KMIP_CLIENT_SUCCESS {
		return nil, errors.New("Failed to retrieve symmetric key from kmip server. Check kmipclient logs for more details.")
	}

	defaultLog.Info("kmipclient/kmipclient:GetSymmetricKey() Retrieved symmetric key from kmip server")
	key := C.GoBytes(keyBuffer, 32)
	return key, nil
}
