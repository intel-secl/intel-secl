/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package keymanager

import (
	"time"

	"github.com/google/uuid"
	"github.com/intel-secl/intel-secl/v5/pkg/kbs/constants"
	"github.com/intel-secl/intel-secl/v5/pkg/kbs/domain/models"
	"github.com/intel-secl/intel-secl/v5/pkg/kbs/kmipclient"
	"github.com/intel-secl/intel-secl/v5/pkg/model/kbs"
	"github.com/pkg/errors"
)

type KmipManager struct {
	client kmipclient.KmipClient
}

func NewKmipManager(c kmipclient.KmipClient) *KmipManager {
	return &KmipManager{c}
}

func (km *KmipManager) CreateKey(request *kbs.KeyRequest) (*models.KeyAttributes, error) {
	defaultLog.Trace("keymanager/kmip_key_manager:CreateKey() Entering")
	defer defaultLog.Trace("keymanager/kmip_key_manager:CreateKey() Leaving")

	keyAttributes := &models.KeyAttributes{
		Algorithm:        request.KeyInformation.Algorithm,
		TransferPolicyId: request.TransferPolicyID,
		Label:            request.Label,
		Usage:            request.Usage,
	}

	switch request.KeyInformation.Algorithm {
	case constants.CRYPTOALG_AES:
		kmipId, err := km.client.CreateSymmetricKey(request.KeyInformation.KeyLength)
		if err != nil {
			return nil, errors.Wrap(err, "failed to create AES key")
		}
		keyAttributes.KeyLength = request.KeyInformation.KeyLength
		keyAttributes.KmipKeyID = kmipId
	case constants.CRYPTOALG_RSA:
		kmipId, err := km.client.CreateAsymmetricKeyPair(constants.CRYPTOALG_RSA, "", request.KeyInformation.KeyLength)
		if err != nil {
			return nil, errors.Wrap(err, "failed to create RSA key pair")
		}
		keyAttributes.KeyLength = request.KeyInformation.KeyLength
		keyAttributes.KmipKeyID = kmipId
	default:
		return nil, errors.Errorf("%s algorithm is not supported", request.KeyInformation.Algorithm)
	}

	newUuid, err := uuid.NewRandom()
	if err != nil {
		return nil, errors.Wrap(err, "failed to create new UUID")
	}
	keyAttributes.ID = newUuid
	keyAttributes.CreatedAt = time.Now().UTC()

	return keyAttributes, nil
}

func (km *KmipManager) DeleteKey(attributes *models.KeyAttributes) error {
	defaultLog.Trace("keymanager/kmip_key_manager:DeleteKey() Entering")
	defer defaultLog.Trace("keymanager/kmip_key_manager:DeleteKey() Leaving")

	if attributes.KmipKeyID == "" {
		return errors.New("key is not created with KMIP key manager")
	}

	return km.client.DeleteKey(attributes.KmipKeyID)
}

func (km *KmipManager) RegisterKey(request *kbs.KeyRequest) (*models.KeyAttributes, error) {
	defaultLog.Trace("keymanager/kmip_key_manager:RegisterKey() Entering")
	defer defaultLog.Trace("keymanager/kmip_key_manager:RegisterKey() Leaving")

	if request.KeyInformation.KmipKeyID == "" {
		return nil, errors.New("kmip_key_id cannot be empty for register operation in kmip mode")
	}

	newUuid, err := uuid.NewRandom()
	if err != nil {
		return nil, errors.Wrap(err, "failed to create new UUID")
	}
	keyAttributes := &models.KeyAttributes{
		ID:               newUuid,
		Algorithm:        request.KeyInformation.Algorithm,
		KeyLength:        request.KeyInformation.KeyLength,
		KmipKeyID:        request.KeyInformation.KmipKeyID,
		TransferPolicyId: request.TransferPolicyID,
		CreatedAt:        time.Now().UTC(),
		Label:            request.Label,
		Usage:            request.Usage,
	}

	return keyAttributes, nil
}

func (km *KmipManager) TransferKey(attributes *models.KeyAttributes) ([]byte, error) {
	defaultLog.Trace("keymanager/kmip_key_manager:TransferKey() Entering")
	defer defaultLog.Trace("keymanager/kmip_key_manager:TransferKey() Leaving")

	if attributes.KmipKeyID == "" {
		return nil, errors.New("key is not created with KMIP key manager")
	}

	if attributes.Algorithm == constants.CRYPTOALG_AES || attributes.Algorithm == constants.CRYPTOALG_RSA {
		return km.client.GetKey(attributes.KmipKeyID, attributes.Algorithm)
	} else {
		return nil, errors.Errorf("%s algorithm is not supported", attributes.Algorithm)
	}
}
