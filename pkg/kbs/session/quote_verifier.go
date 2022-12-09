/*
 * Copyright (C) 2022 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */

package session

import (
	"bytes"
	"encoding/json"
	"net/http"

	"github.com/intel-secl/intel-secl/v5/pkg/model/kbs"

	"github.com/intel-secl/intel-secl/v5/pkg/clients/util"
	"github.com/pkg/errors"

	"github.com/intel-secl/intel-secl/v5/pkg/kbs/config"
	"github.com/intel-secl/intel-secl/v5/pkg/kbs/constants"
	"github.com/intel-secl/intel-secl/v5/pkg/lib/common/crypt"
	"github.com/intel-secl/intel-secl/v5/pkg/lib/common/log"
)

var defaultLog = log.GetDefaultLogger()
var secLog = log.GetSecurityLogger()

// VerifyQuote - Function to verify quote
func VerifyQuote(quote string, nonce string, cfg *config.Configuration, caCertDir string) (*kbs.QuoteVerifyAttributes, error) {
	defaultLog.Trace("session/quote_verifier:VerifyQuote() Entering")
	defer defaultLog.Trace("session/quote_verifier:VerifyQuote() Leaving")

	var quoteData QuoteData
	quoteData.QuoteBlob = quote
	quoteData.UserData = nonce

	caCerts, err := crypt.GetCertsFromDir(caCertDir)
	if err != nil {
		return nil, errors.Wrap(err, "session/quote_verifier:VerifyQuote() Error in retrieving CA certificates")
	}

	buffer := new(bytes.Buffer)
	err = json.NewEncoder(buffer).Encode(quoteData)
	if err != nil {
		return nil, errors.Wrap(err, "session/quote_verifier:VerifyQuote() Error in encoding the quote")
	}

	url := cfg.Skc.SQVSUrl + constants.VerifyQuote
	req, err := http.NewRequest("POST", url, buffer)
	if err != nil {
		return nil, errors.Wrap(err, "session/quote_verifier:VerifyQuote() Error in Creating request")
	}
	req.Header.Add("Accept", "application/json")
	req.Header.Set("Content-Type", "application/json")

	response, err := util.SendRequest(req, cfg.AASBaseUrl, cfg.KBS.Username, cfg.KBS.Password, caCerts)
	if err != nil {
		return nil, errors.Wrap(err, "session/quote_verifier:VerifyQuote() Error getting response body")
	}

	var responseAttributes *kbs.QuoteVerifyAttributes

	err = json.Unmarshal(response, &responseAttributes)
	if err != nil {
		return nil, errors.Wrap(err, "session/quote_verifier:VerifyQuote() Error in unmarshalling response")
	}

	return responseAttributes, nil
}
