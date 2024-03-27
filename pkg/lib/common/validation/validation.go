/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package validation

import (
	"encoding/xml"
	"errors"
	"fmt"
	"net/url"
	"os"
	"regexp"
)

const (
	UUIDReg = "[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-4[a-fA-F0-9]{3}-[8|9|aA|bB][a-fA-F0-9]{3}-[a-fA-F0-9]{12}"
	MaxLen  = 256
)

var (
	nameReg             = regexp.MustCompile(`^[A-Za-z]{1}[A-Za-z0-9_]{1,31}$`)
	issuerDN            = regexp.MustCompile("(^[a-zA-Z0-9-_,.=#+?&;)( ]*$)")
	unameReg            = regexp.MustCompile(`^[A-Za-z]{1}[A-Za-z0-9_]{1,31}$`)
	userorEmailReg      = regexp.MustCompile("^[a-zA-Z0-9.-_]+@?[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$")
	exsiHostUsername    = regexp.MustCompile(`^[a-zA-Z0-9.\-_\\.\\, !#$+=?:{}()\[\]\"|;~'*]+@?[a-zA-Z0-9](?:[a-zA-Z0-9-.\-_\\.\\, !#$+=?:{}()\[\]\"|;~'*]{0,61}[a-zA-Z0-9.\-_\\.\\, !#$+=?:{}()\[\]\"|;~'*])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$`)
	emailReg            = regexp.MustCompile("^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$")
	hostnameReg         = regexp.MustCompile("^(([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\\-]{0,61}[a-zA-Z0-9])\\.)*([A-Za-z0-9]|[A-Za-z0-9][A-Za-z0-9\\-]{0,61}[A-Za-z0-9])$")
	ipReg               = regexp.MustCompile("^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$")
	idfReg              = regexp.MustCompile(`^[a-zA-Z_]{1}[a-zA-Z0-9_]{1,127}$`)
	hardwareuuidReg     = regexp.MustCompile(`^[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{12}$`)
	base64StringReg     = regexp.MustCompile("^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$")
	xmlStringReg        = regexp.MustCompile("(^[a-zA-Z0-9-_\\/.'\",:=<>\n\\/#+?\\[\\]&; ]*$)")
	stringReg           = regexp.MustCompile("(^[a-zA-Z0-9_ \\/.-]*$)")
	hexStringReg        = regexp.MustCompile("^[a-fA-F0-9]+$")
	mrSignerReg         = regexp.MustCompile("^[a-fA-F0-9]{64}$")
	pemEncodedKeyReg    = regexp.MustCompile("(^[-a-zA-Z0-9//=+\012 ]*$)")
	dateReg             = regexp.MustCompile("[0-9]{4}-(0[1-9]|1[0-2])-(0[1-9]|[1-2][0-9]|3[0-1])T(2[0-3]|[01][0-9]):[0-5][0-9]:[0-5][0-9]")
	uuidReg             = regexp.MustCompile("^" + UUIDReg + "$")
	IdReg               = fmt.Sprintf("{id:%s}", UUIDReg)
	portReg             = regexp.MustCompile("(?:([0-9]{1,5}))")
	textReg             = regexp.MustCompile("(?:[a-zA-Z0-9\\[\\]$@(){}_\\.\\, |:-]+)")
	passwordReg         = regexp.MustCompile("(?:([a-zA-Z0-9_\\\\.\\\\, @!#$%^+=>?:{}()\\[\\]\\\"|;~`'*-/]+))")
	connectionStringReg = regexp.MustCompile("^(((vmware)|(microsoft)|(intel))\\:)?(https|nats)\\:\\/\\/.+[\\:\\d+]?(\\/sdk)?((;h=.+;u=.+;p=.+)|(;u=.+;p=.+))?$")
	jwtReg              = regexp.MustCompile("^[A-Za-z0-9-_=]+\\.[A-Za-z0-9-_=]+\\.?[A-Za-z0-9-_.+/=]*")
)

// ValidateEnvList can check if all environment variables in input slice exist
// If things missing, return a slice contains all missing variables and an error.
// Otherwise two nil
func ValidateEnvList(required []string) ([]string, error) {

	missing := make([]string, 0)
	for _, e := range required {
		if _, exist := os.LookupEnv(e); !exist {
			missing = append(missing, e)
		}
	}
	if len(missing) == 0 {
		return nil, nil
	} else {
		return missing, errors.New("One or more required environment variables are missing")
	}
}

// ValidateURL checks if input URL meets the constraints
// protocols is a set of protocols the URL can be supporting, mimicked by a map
// protocol names will be stored in key, and the value is discard
// path is the specified path the URL must follow
// Returns an error if any requirement is not met
func ValidateURL(testURL string, protocols map[string]byte, path string) error {

	urlObj, err := url.ParseRequestURI(testURL)
	if err != nil {
		return errors.New("Invalid base URL")
	}
	if _, exist := protocols[urlObj.Scheme]; !exist {
		return errors.New("Unsupported protocol")
	}
	if urlObj.Path != path {
		return errors.New("Invalid path in URL")
	}
	if urlObj.RawQuery != "" || urlObj.Fragment != "" {
		return errors.New("Unexpected inputs")
	}
	return nil
}

// ValidateAccount information, both username and password primarily forbidding any quotation marks in the input
// as well as restricting the length for both of them
func ValidateAccount(uname string, pwd string) error {

	if unameReg.MatchString(uname) && pwd != "" {
		return nil
	}
	return errors.New("Invalid input for username or password")
}

// ValidateNameString validate user primarily forbidding any quotation marks in the input
// as well as restricting the length.
func ValidateNameString(name string) error {

	if len(name) < MaxLen && nameReg.MatchString(name) {
		return nil
	}
	return errors.New("Invalid input for name")
}

// ValidateUserNameString validate user primarily forbidding any quotation marks in the input
// as well as restricting the length. The username can be in the form of an email address
func ValidateUserNameString(uname string) error {

	if len(uname) < MaxLen && userorEmailReg.MatchString(uname) {
		return nil
	}
	return errors.New("Invalid input for username")
}

func ValidateExsiUserName(uname string) error {

	if len(uname) < MaxLen && exsiHostUsername.MatchString(uname) {
		return nil
	}
	return errors.New("Invalid input for username")
}

// ValidateEmailString validates if user has provided valid email address
func ValidateEmailString(email string) error {

	if len(email) < MaxLen && emailReg.MatchString(email) {
		return nil
	}
	return errors.New("Invalid input for email")
}

// ValidatePasswordString method is used to validate the password string.
func ValidatePasswordString(pwd string) error {

	if len(pwd) < MaxLen && passwordReg.MatchString(pwd) {
		return nil
	}
	return errors.New("Invalid input for password")
}

// ValidateTextString method is used to validate the text string.
func ValidateTextString(text string) error {

	if len(text) < MaxLen && textReg.MatchString(text) {
		return nil
	}
	return errors.New("Invalid input for text")
}

// ValidateHostname method is used to validate the hostname string
func ValidateHostname(hostname string) error {

	if len(hostname) < 254 && (hostnameReg.MatchString(hostname) || ipReg.MatchString(hostname)) {
		return nil
	}
	return errors.New("Invalid hostname or ip")
}

// ValidatePort method is used to validate the port number
func ValidatePort(port string) error {

	if portReg.MatchString(port) {
		return nil
	}
	return errors.New("Invalid port number")
}

// ValidateIdentifier method is used to validate an identifier value
func ValidateIdentifier(idf string) error {

	if idfReg.MatchString(idf) {
		return nil
	}
	return errors.New("Invalid identifier")
}

// ValidateIssuer method is used to validate an issuer value especially in certificates
func ValidateIssuer(isf string) error {

	if issuerDN.MatchString(isf) {
		return nil
	}
	return errors.New("Invalid issuer string")
}

// ValidateStrings method is used to validate input strings
func ValidateStrings(strings []string) error {
	for _, stringValue := range strings {
		if !stringReg.MatchString(stringValue) {
			return errors.New("Invalid string formatted input")
		}
	}
	return nil
}

// ValidatePemEncodedKey method is used to validate input keysin string format
func ValidatePemEncodedKey(key string) error {
	if !pemEncodedKeyReg.MatchString(key) {
		return errors.New("Invalid key format")
	}
	return nil
}

// ValidateBase64String method checks if a string has a valid base64 format
func ValidateBase64String(value string) error {
	if !base64StringReg.MatchString(value) {
		return errors.New("Invalid digest format")
	}
	return nil
}

// ValidateXMLString method checks if a string has a valid base64 format
func ValidateXMLString(value string) error {
	return xml.Unmarshal([]byte(value), new(interface{}))
}

// ValidateHexString method checks if a string has a valid hex format
func ValidateHexString(value string) error {
	if !hexStringReg.MatchString(value) {
		return errors.New("Invalid hex string format")
	}
	return nil
}

// ValidateMrSignerString method checks if a string has a valid hex format with required length
func ValidateMrSignerString(value string) error {
	if !mrSignerReg.MatchString(value) {
		return errors.New("invalid hex string format")
	}
	return nil
}

// ValidateUUIDv4  method is used to check if the given UUID is of valid v4 format
func ValidateUUIDv4(uuid string) error {
	if !uuidReg.MatchString(uuid) {
		return errors.New("Invalid UUID format")
	}
	return nil
}

// ValidateHardwareUUID method is used to check if the hardware UUID format is valid
func ValidateHardwareUUID(uuid string) error {
	if hardwareuuidReg.MatchString(uuid) {
		return nil
	}
	return errors.New("Invalid hardware uuid")
}

// ValidateDate method is used to check if the date format is valid
func ValidateDate(date string) error {
	if dateReg.MatchString(date) {
		return nil
	}
	return errors.New("Invalid date format")
}

// ValidateConnectionString validates the connection string for Create-Host and Create-Flavor APIs
func ValidateConnectionString(cs string) error {
	if connectionStringReg.MatchString(cs) {
		return nil
	}
	return errors.New("Invalid connection string")
}

// ValidateJWT method is used to check if the jwt token format is valid
func ValidateJWT(token string) error {
	if jwtReg.MatchString(token) {
		return nil
	}
	return errors.New("Invalid jwt token format")
}
