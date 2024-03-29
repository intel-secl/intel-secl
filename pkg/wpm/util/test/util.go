/*
 * Copyright (C) 2022 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package testutil

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"

	cLog "github.com/intel-secl/intel-secl/v5/pkg/lib/common/log"

	"github.com/pkg/errors"
)

const (
	wpmTestDir     = "../../../test/wpm/"
	testPublicKey  = wpmTestDir + "publickey.pub"
	testPrivateKey = wpmTestDir + "privatekey.pem"
)

var log = cLog.GetDefaultLogger()

func CreateRSAKeyPair() error {
	log.Trace("pkg/wpm/util/test/util.go:CreateRSAKeyPair() Entering")
	defer log.Trace("pkg/wpm/util/test/util.go:CreateRSAKeyPair() Leaving")

	// Create RSA key pair
	keyPair, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return errors.Wrap(err, "Error while generating new RSA key pair")
	}
	privateKeyBytes := x509.MarshalPKCS1PrivateKey(keyPair)
	// save private key
	privateKey := &pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: privateKeyBytes,
	}

	privateKeyFile, err := os.OpenFile(testPrivateKey, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0600)
	if err != nil {
		return errors.Wrap(err, "I/O error while saving private key file")
	}
	defer func() {
		derr := privateKeyFile.Close()
		if derr != nil {
			fmt.Fprintf(os.Stderr, "Error while closing file"+derr.Error())
		}
	}()
	err = pem.Encode(privateKeyFile, privateKey)
	if err != nil {
		return errors.Wrap(err, "I/O error while encoding private key file")
	}

	publicKey := &keyPair.PublicKey
	pubKeyBytes, _ := x509.MarshalPKIXPublicKey(publicKey)

	publickey := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubKeyBytes,
	}

	pubKeyFile, err := os.OpenFile(testPublicKey, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0600)
	if err != nil {
		return errors.Wrap(err, "I/O error while saving private key file")
	}
	defer func() {
		derr := pubKeyFile.Close()
		if derr != nil {
			fmt.Fprintf(os.Stderr, "Error while closing file"+derr.Error())
		}
	}()
	err = pem.Encode(pubKeyFile, publickey)
	if err != nil {
		return errors.Wrap(err, "I/O error while encoding private key file")
	}
	return nil
}
