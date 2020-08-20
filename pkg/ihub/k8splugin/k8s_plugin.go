/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package k8splugin

import (
	"bytes"
	"crypto"
	"crypto/sha1"
	"encoding/json"
	"strconv"
	"strings"
	"time"

	"github.com/intel-secl/intel-secl/v3/pkg/clients/k8s"
	vsPlugin "github.com/intel-secl/intel-secl/v3/pkg/ihub/attestationPlugin"
	"github.com/intel-secl/intel-secl/v3/pkg/ihub/config"
	"github.com/intel-secl/intel-secl/v3/pkg/ihub/constants"
	model "github.com/intel-secl/intel-secl/v3/pkg/model/k8s"

	"io/ioutil"
	"net/http"
	"net/url"

	commonLog "github.com/intel-secl/intel-secl/v3/pkg/lib/common/log"

	"github.com/dgrijalva/jwt-go"
	"github.com/google/uuid"
	"github.com/pkg/errors"

	"encoding/base64"
)

//KubernetesDetails KubernetesDetails for getting hosts and updating CRD
type KubernetesDetails struct {
	Config          *config.Configuration
	AuthToken       string
	HostDetailsMap  map[string]HostDetails
	PrivateKey      crypto.PrivateKey
	PublicKeyBytes  []byte
	K8sClient       *k8s.Client
}

//HostDetails HostDetails for CRD data to update in kubernetes
type HostDetails struct {
	hostName          string
	hostIP            string
	hostID            uuid.UUID
	trusted           bool
	AssetTags         map[string]string
	HardwareFeatures  map[string]string
	Trust             map[string]string
	SignedTrustReport string
	ValidTo           time.Time
	ReportVerified    bool
}

var log = commonLog.GetDefaultLogger()

//GetHosts Getting Hosts From Kubernetes
func GetHosts(k8sDetails *KubernetesDetails) error {
	log.Trace("k8splugin/k8s_plugin:GetHosts() Entering")
	defer log.Trace("k8splugin/k8s_plugin:GetHosts() Leaving")
	conf := k8sDetails.Config
	urlPath := conf.Endpoint.URL + constants.KubernetesNodesAPI
	log.Debugf("k8splugin/k8s_plugin:GetHosts() URL to get the Hosts : %s", urlPath)

	parsedUrl, err := url.Parse(urlPath)
	if err != nil {
		return errors.Wrap(err, "k8splugin/k8s_plugin:GetHosts() : Unable to parse the url")
	}

	res, err := k8sDetails.K8sClient.SendRequest(&k8s.RequestParams{
		Method: "GET",
		URL:    parsedUrl,
		Body:   nil,
	})
	if err != nil {
		return errors.Wrap(err, "k8splugin/k8s_plugin:GetHosts() : Error in getting the Hosts from kubernetes")
	}

	defer res.Body.Close()
	body, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return errors.Wrap(err, "k8splugin/k8s_plugin:GetHosts() : Error in Reading the Response")
	}

	var hostResponse model.HostResponse
	err = json.Unmarshal(body, &hostResponse)
	if err != nil {
		return errors.Wrap(err, "k8splugin/k8s_plugin:GetHosts() : Error in Unmarshaling the response")
	}

	hostDetailMap := make(map[string]HostDetails)

	for _, items := range hostResponse.Items {

		isMaster := false

		for _, taints := range items.Spec.Taints {
			if taints.Key == "node-role.kubernetes.io/master" {
				isMaster = true
				break
			}
		}
		if !isMaster {
			var hostDetails HostDetails
			sysID := items.Status.NodeInfo.SystemID
			hostDetails.hostID, _ = uuid.Parse(sysID)

			for _, addr := range items.Status.Addresses {

				if addr.Type == "InternalIP" {
					hostDetails.hostIP = addr.Address
				}

				if addr.Type == "Hostname" {
					hostDetails.hostName = addr.Address
				}
			}

			hostDetailMap[hostDetails.hostIP] = hostDetails
		}

	}

	k8sDetails.HostDetailsMap = hostDetailMap
	log.Info("k8splugin/k8s_plugin:GetHosts() List of Host Details : ", k8sDetails.HostDetailsMap)

	return nil
}

//FilterHostReports Get Filtered Host Reports from HVS
func FilterHostReports(k8sDetails *KubernetesDetails, hostDetails *HostDetails, trustedCaDir, samlCertPath string) error {

	log.Trace("k8splugin/k8s_plugin:FilterHostReports() Entering")
	defer log.Trace("k8splugin/k8s_plugin:FilterHostReports() Leaving")

	samlReport, err := vsPlugin.GetHostReports(hostDetails.hostID.String(), k8sDetails.Config, trustedCaDir, samlCertPath)
	if err != nil {
		return errors.Wrap(err, "k8splugin/k8s_plugin:FilterHostReports() : Error in getting the host report")
	}

	trustMap := make(map[string]string)
	hardwareFeaturesMap := make(map[string]string)
	assetTagsMap := make(map[string]string)

	for _, as := range samlReport.Attribute {

		if strings.HasPrefix(as.Name, "TAG") {
			assetTagsMap[as.Name] = as.AttributeValue
		}
		if strings.HasPrefix(as.Name, "TRUST") {
			trustMap[as.Name] = as.AttributeValue
		}
		if strings.HasPrefix(as.Name, "FEATURE") {
			hardwareFeaturesMap[as.Name] = as.AttributeValue
		}

	}

	log.Debug("k8splugin/k8s_plugin:FilterHostReports() Setting Values to Host")

	overAllTrust, _ := strconv.ParseBool(trustMap["TRUST_OVERALL"])
	hostDetails.AssetTags = assetTagsMap
	hostDetails.Trust = trustMap
	hostDetails.HardwareFeatures = hardwareFeaturesMap
	hostDetails.trusted = overAllTrust
	hostDetails.ValidTo = samlReport.Subject.NotOnOrAfter

	return nil
}

//GetSignedTrustReport Creates a Signed trust-report based on the host details
func GetSignedTrustReport(hostList model.HostList, k8sDetails *KubernetesDetails) (string, error) {
	log.Trace("k8splugin/k8s_plugin:GetSignedTrustReport() Entering")
	defer log.Trace("k8splugin/k8s_plugin:GetSignedTrustReport() Leaving")

	hash := sha1.New()
	_, err := hash.Write(k8sDetails.PublicKeyBytes)
	if err != nil {
		return "", errors.Wrap(err, "k8splugin/k8s_plugin:GetSignedTrustReport() : Error in getting digest of Public key")
	}
	sha1Hash := base64.StdEncoding.EncodeToString(hash.Sum(nil))

	token := jwt.NewWithClaims(jwt.SigningMethodRS384, model.HostList{
		HostName:         hostList.HostName,
		AssetTags:        hostList.AssetTags,
		HardwareFeatures: hostList.HardwareFeatures,
		Trust:            hostList.Trust,
		ValidTo:          hostList.ValidTo,
		Trusted:          hostList.Trusted,
	})

	token.Header["kid"] = sha1Hash

	// Create the JWT string
	tokenString, err := token.SignedString(k8sDetails.PrivateKey)
	if err != nil {
		return "", errors.Wrap(err, "k8splugin/k8s_plugin:GetSignedTrustReport() : Error in Getting the signed token")
	}

	return tokenString, nil

}

//UpdateCRD Updates the Kubernetes CRD with details from the host report
func UpdateCRD(k8sDetails *KubernetesDetails) error {

	log.Trace("k8splugin/k8s_plugin:UpdateCRD() Entering")
	defer log.Trace("k8splugin/k8s_plugin:UpdateCRD() Leaving")
	config := k8sDetails.Config
	crdName := config.Endpoint.CRDName
	urlPath := config.Endpoint.URL + constants.KubernetesCRDAPI + crdName

	parsedUrl, err := url.Parse(urlPath)
	if err != nil {
		return errors.Wrap(err, "k8splugin/k8s_plugin:UpdateCRD() : Unable to parse the url")
	}
	res, err := k8sDetails.K8sClient.SendRequest(&k8s.RequestParams{
		Method: "GET",
		URL:    parsedUrl,
		Body:   nil,
	})
	if err != nil {
		return errors.Wrap(err, "k8splugin/k8s_plugin:UpdateCRD() : Error in fetching the kuberenetes CRD")
	}
	var crdResponse model.CRD
	if res.StatusCode == http.StatusOK {

		defer res.Body.Close()
		body, err := ioutil.ReadAll(res.Body)
		if err != nil {
			return errors.Wrap(err, "k8splugin/k8s_plugin:UpdateCRD() : Error in Reading Response body")
		}

		err = json.Unmarshal(body, &crdResponse)
		if err != nil {
			return errors.Wrap(err, "k8splugin/k8s_plugin:UpdateCRD() : Error in UnMarshaling the CRD Reponse")
		}

		log.Debug("k8splugin/k8s_plugin:UpdateCRD() PUT Call to be made")

		k8hostList := crdResponse.Spec.HostList

		for key := range k8sDetails.HostDetailsMap {
			reportHostDetails := k8sDetails.HostDetailsMap[key]
			for n, k8HostDetails := range k8hostList {

				if k8HostDetails.HostName == reportHostDetails.hostName {
					k8hostList[n].AssetTags = reportHostDetails.AssetTags
					k8hostList[n].HardwareFeatures = reportHostDetails.HardwareFeatures
					k8hostList[n].Trust = reportHostDetails.Trust
					k8hostList[n].Trusted = reportHostDetails.trusted
					k8hostList[n].ValidTo = reportHostDetails.ValidTo
					k8hostList[n].SignedTrustReport, err = GetSignedTrustReport(k8hostList[n], k8sDetails)
					if err != nil {
						return errors.Wrap(err, "k8splugin/k8s_plugin:UpdateCRD() : Error in getting the signed trust report")
					}
				}
			}
		}

		crdResponse.Spec.HostList = k8hostList

		err = PutCRD(k8sDetails, &crdResponse)
		if err != nil {
			return errors.Wrap(err, "k8splugin/k8s_plugin:UpdateCRD() : Error in Updating CRD")
		}
	} else {
		log.Debug("k8splugin/k8s_plugin:UpdateCRD() POST Call to be made")

		crdResponse.APIVersion = constants.KubernetesCRDAPIVersion
		crdResponse.Kind = constants.KubernetesCRDKind
		crdResponse.Metadata.Name = crdName
		crdResponse.Metadata.Namespace = constants.KubernetesMetaDataNameSpace
		var hostList []model.HostList

		for key := range k8sDetails.HostDetailsMap {

			reportHostDetails := k8sDetails.HostDetailsMap[key]
			var host model.HostList

			host.HostName = reportHostDetails.hostName
			host.AssetTags = reportHostDetails.AssetTags
			host.HardwareFeatures = reportHostDetails.HardwareFeatures
			host.Trust = reportHostDetails.Trust
			host.Trusted = reportHostDetails.trusted
			host.ValidTo = reportHostDetails.ValidTo
			signedtrustReport, err := GetSignedTrustReport(host, k8sDetails)
			if err != nil {
				return errors.Wrap(err, "k8splugin/k8s_plugin:UpdateCRD() : Error in Getting SignedTrustReport")
			}
			host.SignedTrustReport = signedtrustReport

			hostList = append(hostList, host)
		}

		crdResponse.Spec.HostList = hostList

		log.Debug("k8splugin/k8s_plugin:UpdateCRD() Printing the spec hostList : ", hostList)
		err := PostCRD(k8sDetails, &crdResponse)
		if err != nil {
			return errors.Wrap(err, "k8splugin/k8s_plugin:UpdateCRD() : Error in posting CRD")
		}

	}
	return nil
}

//PutCRD PUT request call to update existing CRD
func PutCRD(k8sDetails *KubernetesDetails, crd *model.CRD) error {

	log.Trace("k8splugin/k8s_plugin:PutCRD() Entering")
	defer log.Trace("k8splugin/k8s_plugin:PutCRD() Leaving")

	config := k8sDetails.Config
	crdName := config.Endpoint.CRDName
	urlPath := config.Endpoint.URL + constants.KubernetesCRDAPI + crdName

	crdJson, err := json.Marshal(crd)
	if err != nil {
		return errors.Wrap(err, "k8splugin/k8s_plugin:PutCRD() Error in Creating JSON object")
	}

	payload := bytes.NewReader(crdJson)

	parsedUrl, err := url.Parse(urlPath)
	if err != nil {
		return errors.Wrap(err, "k8splugin/k8s_plugin:PutCRD() : Unable to parse the url")
	}

	res, err := k8sDetails.K8sClient.SendRequest(&k8s.RequestParams{
		Method:            "PUT",
		URL:               parsedUrl,
		Body:              payload,
		AdditionalHeaders: map[string]string{"Content-Type": "application/json"},
	})

	if err != nil {
		return errors.Wrap(err, "k8splugin/k8s_plugin:PutCRD() Error in creating CRD")
	}

	defer res.Body.Close()

	return nil
}

//PostCRD POST request call to create new CRD
func PostCRD(k8sDetails *KubernetesDetails, crd *model.CRD) error {

	log.Trace("k8splugin/k8s_plugin:PostCRD() Starting")
	defer log.Trace("k8splugin/k8s_plugin:PostCRD() Leaving")
	config := k8sDetails.Config
	crdName := config.Endpoint.CRDName
	urlPath := config.Endpoint.URL + constants.KubernetesCRDAPI + crdName

	crdJSON, err := json.Marshal(crd)
	if err != nil {
		return errors.Wrap(err, "k8splugin/k8s_plugin:PostCRD(): Error in Creating JSON object")
	}
	payload := bytes.NewReader(crdJSON)

	parsedUrl, err := url.Parse(urlPath)
	if err != nil {
		return errors.Wrap(err, "k8splugin/k8s_plugin:PostCRD() : Unable to parse the url")
	}

	_, err = k8sDetails.K8sClient.SendRequest(&k8s.RequestParams{
		Method:            "POST",
		URL:               parsedUrl,
		Body:              payload,
		AdditionalHeaders: map[string]string{"Content-Type": "application/json"},
	})

	if err != nil {
		return errors.Wrap(err, "k8splugin/k8s_plugin: PostCRD() : Error in creating CRD")
	}

	return nil
}

//SendDataToEndPoint pushes host trust data to Kubernetes
func SendDataToEndPoint(kubernetes KubernetesDetails) error {

	log.Trace("k8splugin/k8s_plugin:SendDataToEndPoint() Entering")
	defer log.Trace("k8splugin/k8s_plugin:SendDataToEndPoint() Leaving")

	err := GetHosts(&kubernetes)
	if err != nil {
		return errors.Wrap(err, "k8splugin/k8s_plugin:SendDataToEndPoint() Error in getting the Hosts from kubernetes")
	}

	for key := range kubernetes.HostDetailsMap {
		hostDetails := kubernetes.HostDetailsMap[key]
		err := FilterHostReports(&kubernetes, &hostDetails, constants.TrustedCAsStoreDir, constants.SamlCertFilePath)
		if err != nil {
			log.WithError(err).Error("k8splugin/k8s_plugin:SendDataToEndPoint() Error in Filtering Report for Hosts")
		}
		kubernetes.HostDetailsMap[key] = hostDetails
	}

	err = UpdateCRD(&kubernetes)
	if err != nil {
		return errors.Wrap(err, "k8splugin/k8s_plugin:SendDataToEndPoint() Error in Updating CRDs for Kubernetes")
	}

	return nil
}