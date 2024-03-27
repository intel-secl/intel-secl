/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package utils

import (
	"strings"

	"github.com/intel-secl/intel-secl/v4/pkg/lib/common/validation"
	hcUtil "github.com/intel-secl/intel-secl/v4/pkg/lib/host-connector/util"
	"github.com/pkg/errors"
)

// GetConnectionStringWithoutCredentials remove the username and password from the connection string and returns it back. This
// would be stored in the host table and the credentials would be stored in the separate table.
func GetConnectionStringWithoutCredentials(cs string) string {
	defaultLog.Trace("utils/connection_string:GetConnectionStringWithoutCredentials() Entering")
	defer defaultLog.Trace("utils/connection_string:GetConnectionStringWithoutCredentials() Leaving")

	csParts := strings.Split(cs, ";")
	for i := 0; i < len(csParts); i++ {
		if strings.HasPrefix(csParts[i], "u=") || strings.HasPrefix(csParts[i], "p=") {
			csParts = append(csParts[:i], csParts[i+1:]...)
			i--
		}
	}
	return strings.Join(csParts, ";")
}

func ValidateConnectionString(cs string) error {
	defaultLog.Trace("util/connection_string:ValidateConnectionString() Entering")
	defer defaultLog.Trace("util/connection_string:ValidateConnectionString() Leaving")

	vc, err := hcUtil.GetConnectorDetails(cs)
	if err != nil {
		return errors.Wrap(err, "Invalid URL in connection string")
	}

	// TODO: Validate host and port in url
	// need to change the type to URL*
	// changes needed in host connector

	if vc.Configuration.Hostname != "" {
		if err := validation.ValidateHostname(vc.Configuration.Hostname); err != nil {
			return errors.Wrap(err, "Invalid hostname or IP address")
		}
	}
	if vc.Configuration.Password != "" {
		if err := validation.ValidatePasswordString(vc.Configuration.Password); err != nil {
			return errors.Wrap(err, "Invalid password")
		}
	}
	if vc.Configuration.Username != "" {
		if err := validation.ValidateExsiUserName(vc.Configuration.Username); err != nil {
			return errors.Wrap(err, "Invalid username")
		}
	}
	return nil
}
