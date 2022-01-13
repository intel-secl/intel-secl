/*
 * Copyright (C) 2021 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package common

import (
	"encoding/pem"
	"io/ioutil"
	"os"

	"github.com/intel-secl/intel-secl/v5/pkg/tagent/constants"

	"github.com/pkg/errors"
)

func (handler *requestHandlerImpl) GetAikDerBytes() ([]byte, error) {
	aikBytes, err := GetAikPem()
	if err != nil {
		return nil, err
	}

	aikDer, _ := pem.Decode(aikBytes)
	if aikDer == nil {
		return nil, errors.New("There was an error parsing the aik's der bytes")
	}

	return aikDer.Bytes, nil
}

func GetAikPem() ([]byte, error) {
	if _, err := os.Stat(constants.AikCert); os.IsNotExist(err) {
		return nil, errors.Wrapf(err, "AIK %s does not exist", constants.AikCert)
	}

	aikPem, err := ioutil.ReadFile(constants.AikCert)
	if err != nil {
		return nil, errors.Wrap(err, "Error reading aik")
	}

	return aikPem, nil
}
