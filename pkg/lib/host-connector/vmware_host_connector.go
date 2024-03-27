/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package host_connector

import (
	"crypto"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/intel-secl/intel-secl/v4/pkg/model/hvs"
	"reflect"
	"sort"
	"strconv"
	"strings"

	"github.com/intel-secl/intel-secl/v4/pkg/clients/vmware"
	"github.com/intel-secl/intel-secl/v4/pkg/lib/common/crypt"
	"github.com/intel-secl/intel-secl/v4/pkg/lib/flavor/constants"
	"github.com/intel-secl/intel-secl/v4/pkg/lib/host-connector/types"
	taModel "github.com/intel-secl/intel-secl/v4/pkg/model/ta"
	"github.com/pkg/errors"
	"github.com/vmware/govmomi/vim25/mo"
	vim25Types "github.com/vmware/govmomi/vim25/types"
)

type VmwareConnector struct {
	client vmware.VMWareClient
}

const (
	TPM_SOFTWARE_COMPONENT_EVENT_TYPE   = "HostTpmSoftwareComponentEvent"
	TPM_COMMAND_EVENT_TYPE              = "HostTpmCommandEvent"
	TPM_OPTION_EVENT_TYPE               = "HostTpmOptionEvent"
	TPM_BOOT_SECURITY_OPTION_EVENT_TYPE = "HostTpmBootSecurityOptionEvent"
	TPM_BOOT_COMPLETE_EVENT_TYPE        = "HostTpmBootCompleteEvent"
	TPM_BOOT_COMPLETE_EVENT_NAME        = "TPM_BOOT_COMPLETE"
	COMPONENT_PREFIX                    = "componentName."
	COMMANDLINE_PREFIX                  = "commandLine."
	VIM_API_PREFIX                      = "Vim25Api."
	DETAILS_SUFFIX                      = "Details"
	BOOT_OPTIONS_PREFIX                 = "bootOptions."
	BOOT_SECURITY_OPTIONS_PREFIX        = "bootSecurityOption."
	VIB_NAME_TYPE_ID                    = "0x60000001"
	COMMANDLINE_TYPE_ID                 = "0x60000002"
	OPTIONS_FILE_NAME_TYPE_ID           = "0x60000003"
	BOOT_SECURITY_OPTION_TYPE_ID        = "0x60000004"
	BOOT_COMPLETE_TYPE_ID               = "0x60000005"
)

func (vc *VmwareConnector) GetHostDetails() (taModel.HostInfo, error) {

	log.Trace("vmware_host_connector :GetHostDetails() Entering")
	defer log.Trace("vmware_host_connector :GetHostDetails() Leaving")
	hostInfo, err := vc.client.GetHostInfo()
	if err != nil {
		return taModel.HostInfo{}, errors.Wrap(err, "vmware_host_connector: GetHostDetails() Error getting host"+
			"info from vmware")
	}
	return hostInfo, nil
}

func (vc *VmwareConnector) GetHostManifest(pcrList []int) (hvs.HostManifest, error) {

	log.Trace("vmware_host_connector :GetHostManifest() Entering")
	defer log.Trace("vmware_host_connector :GetHostManifest() Leaving")
	var err error
	var hostManifest hvs.HostManifest
	var pcrManifest hvs.PcrManifest
	tpmAttestationReport, err := vc.client.GetTPMAttestationReport()
	if err != nil {
		return hvs.HostManifest{}, errors.Wrap(err, "vmware_host_connector: GetHostManifest() Error getting TPM "+
			"attestation report from vcenter API")
	}

	//Check if TPM log is reliable
	if !tpmAttestationReport.Returnval.TpmLogReliable {
		return hvs.HostManifest{}, errors.New("vmware_host_connector: GetHostManifest() TPM log received from" +
			"VMware host is not reliable")
	}
	pcrManifest, pcrsDigest, err := createPCRManifest(tpmAttestationReport.Returnval, pcrList)
	if err != nil {
		return hvs.HostManifest{}, errors.Wrap(err, "vmware_host_connector: GetHostManifest() Error parsing "+
			"PCR manifest from Host Attestation Report")
	}

	hostManifest.HostInfo, err = vc.client.GetHostInfo()
	log.Debugf("Host info received : %v", hostManifest.HostInfo)
	if err != nil {
		return hvs.HostManifest{}, errors.Wrap(err, "vmware_host_connector: GetHostManifest() Error getting host "+
			"info from vcenter API")
	}
	hostManifest.PcrManifest = pcrManifest
	hostManifest.QuoteDigest = pcrsDigest
	return hostManifest, nil
}

func (vc *VmwareConnector) DeployAssetTag(hardwareUUID, tag string) error {
	return errors.New("vmware_host_connector:DeployAssetTag() Operation not supported")
}

func (vc *VmwareConnector) DeploySoftwareManifest(manifest taModel.Manifest) error {
	return errors.New("vmware_host_connector :DeploySoftwareManifest() Operation not supported")
}

func (vc *VmwareConnector) GetMeasurementFromManifest(manifest taModel.Manifest) (taModel.Measurement, error) {
	return taModel.Measurement{}, errors.New("vmware_host_connector :GetMeasurementFromManifest() Operation not supported")
}

func (vc *VmwareConnector) GetClusterReference(clusterName string) ([]mo.HostSystem, error) {
	log.Trace("vmware_host_connector :GetClusterReference() Entering")
	defer log.Trace("vmware_host_connector :GetClusterReference() Leaving")
	hostInfoList, err := vc.client.GetVmwareClusterReference(clusterName)
	if err != nil {
		return nil, errors.Wrap(err, "vmware_host_connector: GetClusterReference() Error getting host"+
			"info from vmware")
	}
	return hostInfoList, nil
}

func createPCRManifest(hostTpmAttestationReport *vim25Types.HostTpmAttestationReport, pcrList []int) (hvs.PcrManifest, string, error) {

	log.Trace("vmware_host_connector :createPCRManifest() Entering")
	defer log.Trace("vmware_host_connector :createPCRManifest() Leaving")

	var pcrManifest hvs.PcrManifest
	pcrManifest.Sha256Pcrs = []hvs.HostManifestPcrs{}
	pcrManifest.Sha1Pcrs = []hvs.HostManifestPcrs{}
	pcrManifest.Sha384Pcrs = []hvs.HostManifestPcrs{}
	var pcrEventLogMap hvs.PcrEventLogMap
	cumulativePcrsValue := ""

	for _, pcrDetails := range hostTpmAttestationReport.TpmPcrValues {
		pcrIndex, err := hvs.GetPcrIndexFromString(strconv.Itoa(int(pcrDetails.PcrNumber)))
		if err != nil {
			return pcrManifest, "", err
		}
		shaAlgorithm, err := hvs.GetSHAAlgorithm(pcrDetails.DigestMethod)
		if err != nil {
			return pcrManifest, "", err
		}

		if strings.EqualFold(pcrDetails.DigestMethod, constants.SHA256) {
			pcrManifest.Sha256Pcrs = append(pcrManifest.Sha256Pcrs, hvs.HostManifestPcrs{
				Index:   pcrIndex,
				Value:   intArrayToHexString(pcrDetails.DigestValue),
				PcrBank: shaAlgorithm,
			})
		} else if strings.EqualFold(pcrDetails.DigestMethod, constants.SHA1) {
			pcrManifest.Sha1Pcrs = append(pcrManifest.Sha1Pcrs, hvs.HostManifestPcrs{
				Index:   pcrIndex,
				Value:   intArrayToHexString(pcrDetails.DigestValue),
				PcrBank: shaAlgorithm,
			})
		} else if strings.EqualFold(pcrDetails.DigestMethod, constants.SHA384) {
			pcrManifest.Sha384Pcrs = append(pcrManifest.Sha384Pcrs, hvs.HostManifestPcrs{
				Index:   pcrIndex,
				Value:   intArrayToHexString(pcrDetails.DigestValue),
				PcrBank: shaAlgorithm,
			})
		} else {
			log.Warn("vmware_host_connector:createPCRManifest() Result PCR invalid")
		}
	}
	pcrEventLogMap, err := getPcrEventLog(hostTpmAttestationReport.TpmEvents, pcrEventLogMap)
	if err != nil {
		log.Errorf("vmware_host_connector:createPCRManifest() Error getting PCR event log : %s", err.Error())
		return pcrManifest, "", errors.Wrap(err, "vmware_host_connector:createPCRManifest() Error getting PCR "+
			"event log")
	}
	//Evaluate digest
	pcrsDigestBytes, err := crypt.GetHashData([]byte(cumulativePcrsValue), crypto.SHA384)
	if err != nil {
		log.Errorf("vmware_host_connector:createPCRManifest() Error evaluating PCRs digest : %s", err.Error())
		return pcrManifest, "", errors.Wrap(err, "vmware_host_connector:createPCRManifest() Error evaluating "+
			"PCRs digest")
	}
	pcrsDigest := hex.EncodeToString(pcrsDigestBytes)
	pcrManifest.PcrEventLogMap = pcrEventLogMap
	return pcrManifest, pcrsDigest, nil
}

func getPcrEventLog(hostTpmEventLogEntry []vim25Types.HostTpmEventLogEntry, eventLogMap hvs.PcrEventLogMap) (hvs.PcrEventLogMap, error) {

	log.Trace("vmware_host_connector:getPcrEventLog() Entering")
	defer log.Trace("vmware_host_connector:getPcrEventLog() Leaving")

	eventLogMap.Sha1EventLogs = []hvs.TpmEventLog{}
	eventLogMap.Sha256EventLogs = []hvs.TpmEventLog{}
	eventLogMap.Sha384EventLogs = []hvs.TpmEventLog{}

	for _, eventLogEntry := range hostTpmEventLogEntry {
		pcrFound := false
		index := 0
		parsedEventLogEntry := types.TpmEvent{}

		//This is done to preserve the dynamic data i.e the info of the event details
		marshalledEntry, err := json.Marshal(eventLogEntry)
		log.Debugf("Marshalled event log : %s", string(marshalledEntry))
		if err != nil {
			return hvs.PcrEventLogMap{}, errors.Wrap(err, "vmware_host_connector:getPcrEventLog() Error "+
				"unmarshalling TPM event")
		}
		//Unmarshal to structure to get the inaccessible fields from event details JSON
		err = json.Unmarshal(marshalledEntry, &parsedEventLogEntry)
		if err != nil {
			return hvs.PcrEventLogMap{}, err
		}
		eventLogEntryType := getType(eventLogEntry.EventDetails)
		//vCenter 6.5 only supports SHA1 digest and hence do not have digest method field. Also if the hash is 0 they
		//send out 40 0s instead of 20
		if len(parsedEventLogEntry.EventDetails.DataHash) == sha1.Size || len(parsedEventLogEntry.EventDetails.DataHash) == 40 {
			parsedEventLogEntry.EventDetails.DataHashMethod = constants.SHA1
			for _, entry := range eventLogMap.Sha1EventLogs {
				if entry.Pcr.Index == parsedEventLogEntry.PcrIndex {
					pcrFound = true
					break
				}
				index++
			}
			eventLog := getEventLogInfo(parsedEventLogEntry, eventLogEntryType)

			if !pcrFound {
				eventLogMap.Sha1EventLogs = append(eventLogMap.Sha1EventLogs, hvs.TpmEventLog{Pcr: hvs.Pcr{Index: parsedEventLogEntry.PcrIndex, Bank: string(parsedEventLogEntry.EventDetails.DataHashMethod)}, TpmEvent: []hvs.EventLog{eventLog}})
			} else {
				eventLogMap.Sha1EventLogs[index].TpmEvent = append(eventLogMap.Sha1EventLogs[index].TpmEvent, eventLog)
			}
		} else if len(parsedEventLogEntry.EventDetails.DataHash) == sha256.Size {
			parsedEventLogEntry.EventDetails.DataHashMethod = constants.SHA256
			for _, entry := range eventLogMap.Sha256EventLogs {
				if entry.Pcr.Index == parsedEventLogEntry.PcrIndex {
					pcrFound = true
					break
				}
				index++
			}

			eventLog := getEventLogInfo(parsedEventLogEntry, eventLogEntryType)

			if !pcrFound {
				eventLogMap.Sha256EventLogs = append(eventLogMap.Sha256EventLogs,
					hvs.TpmEventLog{Pcr: hvs.Pcr{Index: parsedEventLogEntry.PcrIndex, Bank: string(parsedEventLogEntry.EventDetails.DataHashMethod)}, TpmEvent: []hvs.EventLog{eventLog}})
			} else {
				eventLogMap.Sha256EventLogs[index].TpmEvent = append(eventLogMap.Sha256EventLogs[index].TpmEvent, eventLog)
			}
		} else if len(parsedEventLogEntry.EventDetails.DataHash) == sha512.Size384 {
			parsedEventLogEntry.EventDetails.DataHashMethod = constants.SHA384
			for _, entry := range eventLogMap.Sha384EventLogs {
				if entry.Pcr.Index == parsedEventLogEntry.PcrIndex {
					pcrFound = true
					break
				}
				index++
			}

			eventLog := getEventLogInfo(parsedEventLogEntry, eventLogEntryType)

			if !pcrFound {
				eventLogMap.Sha384EventLogs = append(eventLogMap.Sha384EventLogs,
					hvs.TpmEventLog{Pcr: hvs.Pcr{Index: parsedEventLogEntry.PcrIndex, Bank: string(parsedEventLogEntry.EventDetails.DataHashMethod)}, TpmEvent: []hvs.EventLog{eventLog}})
			} else {
				eventLogMap.Sha384EventLogs[index].TpmEvent = append(eventLogMap.Sha384EventLogs[index].TpmEvent, eventLog)
			}
		}

	}

	//Sort the event log map so that the PCR indices are in order
	sort.SliceStable(eventLogMap.Sha1EventLogs[:], func(i, j int) bool {
		return fmt.Sprintf("%d", eventLogMap.Sha1EventLogs[i].Pcr.Index) < fmt.Sprintf("%d", eventLogMap.Sha1EventLogs[j].Pcr.Index)
	})

	sort.SliceStable(eventLogMap.Sha256EventLogs[:], func(i, j int) bool {
		return fmt.Sprintf("%d", eventLogMap.Sha256EventLogs[i].Pcr.Index) < fmt.Sprintf("%d", eventLogMap.Sha256EventLogs[j].Pcr.Index)
	})

	sort.SliceStable(eventLogMap.Sha384EventLogs[:], func(i, j int) bool {
		return fmt.Sprintf("%d", eventLogMap.Sha384EventLogs[i].Pcr.Index) < fmt.Sprintf("%d", eventLogMap.Sha384EventLogs[j].Pcr.Index)
	})

	log.Debug("vmware_host_connector:getPcrEventLog() PCR event log created")
	return eventLogMap, nil
}

func intArrayToHexString(pcrDigestArray []int) string {
	log.Trace("vmware_host_connector:intArrayToHexString() Entering")
	defer log.Trace("vmware_host_connector:intArrayToHexString() Leaving")
	var pcrDigestString string

	//if the hash is 0 then vcenter 6.5 API sends out 40 0s instead of 20 for SHA1
	if len(pcrDigestArray) == 40 {
		pcrDigestArray = pcrDigestArray[0:20]
	}

	for _, element := range pcrDigestArray {
		if element < 0 {
			element = 256 + element
		}
		pcrDigestString += fmt.Sprintf("%02x", element)
	}
	return pcrDigestString
}

// It checks the type of TPM event and accordingly updates the event log entry values
func getEventLogInfo(parsedEventLogEntry types.TpmEvent, eventLogEntryType string) hvs.EventLog {

	log.Trace("vmware_host_connector:getEventLogInfo() Entering")
	defer log.Trace("vmware_host_connector:getEventLogInfo() Leaving")
	eventLog := hvs.EventLog{Measurement: intArrayToHexString(parsedEventLogEntry.EventDetails.DataHash)}

	if parsedEventLogEntry.EventDetails.VibName != nil {
		eventLog.TypeID = VIB_NAME_TYPE_ID
		eventLog.TypeName = *parsedEventLogEntry.EventDetails.ComponentName
		eventLog.Tags = append(eventLog.Tags, COMPONENT_PREFIX+*parsedEventLogEntry.EventDetails.ComponentName)
		if *parsedEventLogEntry.EventDetails.VibName != "" {
			eventLog.Tags = append(eventLog.Tags, VIM_API_PREFIX+TPM_SOFTWARE_COMPONENT_EVENT_TYPE+DETAILS_SUFFIX+"_"+*parsedEventLogEntry.EventDetails.VibName+"_"+*parsedEventLogEntry.EventDetails.VibVendor)
		} else {
			eventLog.Tags = append(eventLog.Tags, VIM_API_PREFIX+TPM_SOFTWARE_COMPONENT_EVENT_TYPE+DETAILS_SUFFIX)
		}
	} else if parsedEventLogEntry.EventDetails.CommandLine != nil {
		eventLog.TypeID = COMMANDLINE_TYPE_ID
		uuid := getBootUUIDFromCL(*parsedEventLogEntry.EventDetails.CommandLine)
		if uuid != "" {
			eventLog.Tags = append(eventLog.Tags, COMMANDLINE_PREFIX)
		} else {
			eventLog.Tags = append(eventLog.Tags, COMMANDLINE_PREFIX+*parsedEventLogEntry.EventDetails.CommandLine)
		}
		eventLog.TypeName = *parsedEventLogEntry.EventDetails.CommandLine
		eventLog.Tags = append(eventLog.Tags, VIM_API_PREFIX+TPM_COMMAND_EVENT_TYPE+DETAILS_SUFFIX)

	} else if parsedEventLogEntry.EventDetails.OptionsFileName != nil {
		eventLog.TypeID = OPTIONS_FILE_NAME_TYPE_ID
		eventLog.TypeName = *parsedEventLogEntry.EventDetails.OptionsFileName
		eventLog.Tags = append(eventLog.Tags, BOOT_OPTIONS_PREFIX+*parsedEventLogEntry.EventDetails.OptionsFileName)
		eventLog.Tags = append(eventLog.Tags, VIM_API_PREFIX+TPM_OPTION_EVENT_TYPE+DETAILS_SUFFIX)

	} else if parsedEventLogEntry.EventDetails.BootSecurityOption != nil {
		eventLog.TypeID = BOOT_SECURITY_OPTION_TYPE_ID
		eventLog.TypeName = *parsedEventLogEntry.EventDetails.BootSecurityOption
		eventLog.Tags = append(eventLog.Tags, BOOT_SECURITY_OPTIONS_PREFIX+*parsedEventLogEntry.EventDetails.BootSecurityOption)
		eventLog.Tags = append(eventLog.Tags, VIM_API_PREFIX+TPM_BOOT_SECURITY_OPTION_EVENT_TYPE+DETAILS_SUFFIX)
	} else if eventLogEntryType == TPM_BOOT_COMPLETE_EVENT_TYPE+DETAILS_SUFFIX {
		eventLog.TypeID = BOOT_COMPLETE_TYPE_ID
		eventLog.TypeName = TPM_BOOT_COMPLETE_EVENT_NAME
		eventLog.Tags = append(eventLog.Tags, BOOT_OPTIONS_PREFIX+TPM_BOOT_COMPLETE_EVENT_NAME)
		eventLog.Tags = append(eventLog.Tags, VIM_API_PREFIX+TPM_BOOT_COMPLETE_EVENT_TYPE+DETAILS_SUFFIX)
	} else {
		log.Warn("Unrecognized event in module event log")
	}

	return eventLog
}

func getType(x interface{}) string {
	if t := reflect.TypeOf(x); t.Kind() == reflect.Ptr {
		return t.Elem().Name()
	} else {
		return t.Name()
	}
}

func getBootUUIDFromCL(commandLine string) string {
	log.Trace("vmware_host_connector:getBootUUIDFromCL() Entering")
	defer log.Trace("vmware_host_connector:getBootUUIDFromCL() Leaving")
	for _, word := range strings.Split(commandLine, " ") {
		if strings.Contains(word, "bootUUID") {
			return strings.Split(word, "=")[1]
		}
	}
	return ""
}
