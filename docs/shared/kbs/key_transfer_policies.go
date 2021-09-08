/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package kbs

import "github.com/intel-secl/intel-secl/v5/pkg/model/kbs"

type KeyTransferPolicies []kbs.KeyTransferPolicy

// KeyTransferPolicy request/response payload
// swagger:parameters KeyTransferPolicy
type KeyTransferPolicy struct {
	// in:body
	Body kbs.KeyTransferPolicy
}

// KeyTransferPolicyCollection response payload
// swagger:parameters KeyTransferPolicyCollection
type KeyTransferPolicyCollection struct {
	// in:body
	Body KeyTransferPolicies
}

// ---

// swagger:operation POST /key-transfer-policies KeyTransferPolicies CreateKeyTransferPolicy
// ---
//
// description: |
//   Creates a key transfer policy. Transfer-Policy with only one attestation-type i.e; SGX or TDX could be created at a time. Key transfer policy can be created
//   either by providing only list of policy-ids or only TDX/SGX attributes or both policy-ids and attributes.
//
//   The serialized KeyTransferPolicy Go struct object represents the content of the request body.
//
//    | Attribute                                    | Description |
//    |----------------------------------------------|-------------|
//    | attestation_type                             | Array of Attestation Type identifiers that client must support to get the key. Expect client to advertise these with the key request e.g. "SGX", "TDX" (note that if key server needs to restrict technologies, then it should list only the ones that can receive the key). |
//    | mr_signer                                    | Array of measurements of SGX enclave’s code signing certificate. This is mandatory. The same issuer must be added as a trusted certificate in key server configuration settings. |
//    | isv_prod_id                                  | Array of (16-bit value) (ISVPRODID). This is mandatory. This is like a qualifier for the issuer so same issuer (code signing) key can sign separate products. |
//    | isv_ext_prod_id                              | Array of (16-byte value) (ISVPRODID). This is like a qualifier for the issuer so same issuer key can sign separate products, it's like product id but simply bigger (starts in Coffee Lake). |
//    | mr_enclave                                   | Array of enclave measurements that are allowed to retrieve the key (MRENCLAVE). Expect client to have one of these measurements in the SGX quote (this supports use case of providing key only to an SGX enclave that will enforce the key usage policy locally). |
//    | config_svn                                   | Integer. |
//    | isv_svn                                      | Minimum security version number required for Enclave. |
//    | config_id                                    | Array of config id measurements that are allowed to retrieve the key. Required value for the enclave to have when it launched. for loading e.g. Java applets into enclavized JVM, so that enclave measurement is JVM measurement, and when it launches it's configured with this id, so when it loads applet it can measure it and compare to config id in register, and refuse to load applet if wrong (starts in Coffee Lake). |
//    | client_permissions                           | Array of permission to expect in client api key. Expect client api key to have all of these names. |
//    | mr_signer_seam                               | Array of measurements of seam module issuer. This is mandatory. |
//    | mr_seam                                      | Array of measurements of seam module. This is mandatory. |
//    | mr_td                                        | Array of TD measurements. |
//    | rtmr0                                        | Measurement extended to RTMR0. |
//    | rtmr1                                        | Measurement extended to RTMR1. |
//    | rtmr2                                        | Measurement extended to RTMR2. |
//    | rtmr3                                        | Measurement extended to RTMR3. |
//    | seam_svn                                     | Minimum security version number of seam module. |
//    | enforce_tcb_upto_date                        | Boolean value to enforce Up-To-Date TCB. |
//    | policy_ids                                   | Array of TD/Enclave Attestation Policy Ids. |
//
// x-permissions: keys-transfer-policies:create
// security:
//  - bearerAuth: []
// produces:
// - application/json
// consumes:
// - application/json
// parameters:
// - name: request body
//   required: true
//   in: body
//   schema:
//    "$ref": "#/definitions/KeyTransferPolicy"
// - name: Content-Type
//   description: Content-Type header
//   in: header
//   type: string
//   required: true
//   enum:
//     - application/json
// - name: Accept
//   description: Accept header
//   in: header
//   type: string
//   required: true
//   enum:
//     - application/json
// responses:
//   '201':
//     description: Successfully created the key transfer policy.
//     content:
//       application/json
//     schema:
//       $ref: "#/definitions/KeyTransferPolicy"
//   '400':
//     description: Invalid request body provided
//   '415':
//     description: Invalid Accept Header in Request
//   '500':
//     description: Internal server error
//
// x-sample-call-endpoint: https://kbs.com:9443/kbs/v1/key-transfer-policies
// x-sgx-sample-call-input: |
//    {
//      "attestation_type": ["SGX"],
//      "sgx": {
//          "attributes": {
//              "mr_signer": ["cd171c56941c6ce49690b455f691d9c8a04c2e43e0a4d30f752fa5285c7ee57f"],
//              "isv_prod_id": [12],
//              "isv_ext_prod_id": ["00000000000000000000000000000000"],
//              "mr_enclave": ["01c60b9617b2f96e53cb75ef01e0dccea3afc7b7992697eabb8f714b2ccd1953"],
//              "config_svn": 0,
//              "isv_svn": 1,
//              "config_id": ["00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"],
//              "client_permissions":["nginx","USA"],
//              "enforce_tcb_upto_date": false
//          },
//          "policy_ids": ["37965f5f-ccaf-4cdc-a356-a8ed5268a5bf", "9846bf40-e380-4842-ae15-1b60996d1190"]
//      }
//    }
// x-sgx-sample-call-output: |
//    {
//      "id": "d0c3f191-80f9-408f-a690-0dde00ba65ac",
//      "created_at": "2021-08-20T06:30:35.085644391Z",
//      "attestation_type": [
//          "SGX"
//      ],
//      "sgx": {
//        "attributes": {
//            "mr_signer": [
//                "cd171c56941c6ce49690b455f691d9c8a04c2e43e0a4d30f752fa5285c7ee57f"
//            ],
//            "isv_prod_id": [
//                12
//            ],
//            "isv_ext_prod_id": [
//                "00000000000000000000000000000000"
//            ],
//            "mr_enclave": [
//                "01c60b9617b2f96e53cb75ef01e0dccea3afc7b7992697eabb8f714b2ccd1953"
//            ],
//            "config_svn": 0,
//            "isv_svn": 1,
//            "config_id": [
//                "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
//            ],
//            "client_permissions": [
//                "nginx",
//                "USA"
//            ],
//            "enforce_tcb_upto_date": false
//        },
//        "policy_ids": [
//            "37965f5f-ccaf-4cdc-a356-a8ed5268a5bf",
//            "9846bf40-e380-4842-ae15-1b60996d1190"
//        ]
//      }
//    }
// x-tdx-sample-call-input: |
//    {
//      "attestation_type": [
//          "TDX"
//      ],
//      "tdx": {
//        "attributes": {
//            "mr_signer_seam": [
//                "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
//            ],
//            "mr_seam": [
//                "0f3b72d0f9606086d6a7800e7d50b82fa6cb5ec64c7210353a0696c1eef343679bf5b9e8ec0bf58ab3fce10f2c166ebe"
//            ],
//            "mrtd": [
//                "cf656414fc0f49b23e2ae64b6f23b82901e2206aab36b671e360ebd414899dab51bbb60134bbe6ad8dcc70b995d9dc50"
//            ],
//            "rtmr0": "b90abd43736381b12fc9b038924c73e31c8371674905e7fcb7941d69fe59d30eda3adb9e41b878151e756fb05ad13d14",
//            "rtmr1": "a53c98b16f0de470338e7f072d9c5fcef6171327ec6c78b842e637251b1de6e37354c47fb68de27ef14bb67caf288d9b",
//            "rtmr2": "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
//            "rtmr3": "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
//            "seam_svn": 0,
//            "enforce_tcb_upto_date": false
//        },
//        "policy_ids": [
//            "37965f5f-ccaf-4cdc-a356-a8ed5268a5bf", "9846bf40-e380-4842-ae15-1b60996d1190"
//        ]
//      }
//    }
// x-tdx-sample-call-output: |
//    {
//      "id": "cf9adfcf-4bfa-4653-b9b8-2b94beca768f",
//      "created_at": "2021-08-20T05:51:39.588320016Z",
//      "attestation_type": [
//          "TDX"
//      ],
//      "tdx": {
//        "attributes": {
//            "mr_signer_seam": [
//                "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
//            ],
//            "mr_seam": [
//                "0f3b72d0f9606086d6a7800e7d50b82fa6cb5ec64c7210353a0696c1eef343679bf5b9e8ec0bf58ab3fce10f2c166ebe"
//            ],
//            "seam_svn": 0,
//            "mrtd": [
//                "cf656414fc0f49b23e2ae64b6f23b82901e2206aab36b671e360ebd414899dab51bbb60134bbe6ad8dcc70b995d9dc50"
//            ],
//            "rtmr0": "b90abd43736381b12fc9b038924c73e31c8371674905e7fcb7941d69fe59d30eda3adb9e41b878151e756fb05ad13d14",
//            "rtmr1": "a53c98b16f0de470338e7f072d9c5fcef6171327ec6c78b842e637251b1de6e37354c47fb68de27ef14bb67caf288d9b",
//            "rtmr2": "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
//            "rtmr3": "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
//            "enforce_tcb_upto_date": false
//        },
//        "policy_ids": [
//            "37965f5f-ccaf-4cdc-a356-a8ed5268a5bf",
//            "9846bf40-e380-4842-ae15-1b60996d1190"
//        ]
//      }
//    }

// ---

// swagger:operation GET /key-transfer-policies/{id} KeyTransferPolicies RetrieveKeyTransferPolicy
// ---
//
// description: |
//   Retrieves a key transfer policy.
//   Returns - The serialized KeyTransferPolicy Go struct object that was retrieved.
// x-permissions: keys-transfer-policies:retrieve
// security:
//  - bearerAuth: []
// produces:
// - application/json
// parameters:
// - name: id
//   description: Unique ID of the key transfer policy.
//   in: path
//   required: true
//   type: string
//   format: uuid
// - name: Accept
//   description: Accept header
//   in: header
//   type: string
//   required: true
//   enum:
//     - application/json
// responses:
//   '200':
//     description: Successfully retrieved the key transfer policy.
//     content:
//       application/json
//     schema:
//       $ref: "#/definitions/KeyTransferPolicy"
//   '404':
//     description: KeyTransferPolicy record not found
//   '415':
//     description: Invalid Accept Header in Request
//   '500':
//     description: Internal server error
//
// x-sample-call-endpoint: https://kbs.com:9443/kbs/v1/key-transfer-policies/75d34bf4-80fb-4ca5-8602-a8d82e56b30d
// x-sample-call-output: |
//    {
//      "id": "75d34bf4-80fb-4ca5-8602-a8d82e56b30d",
//      "created_at": "2021-08-20T05:51:39.588320016Z",
//      "attestation_type": [
//          "TDX"
//      ],
//      "tdx": {
//        "attributes": {
//            "mr_signer_seam": [
//                "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
//            ],
//            "mr_seam": [
//                "0f3b72d0f9606086d6a7800e7d50b82fa6cb5ec64c7210353a0696c1eef343679bf5b9e8ec0bf58ab3fce10f2c166ebe"
//            ],
//            "seam_svn": 0,
//            "mrtd": [
//                "cf656414fc0f49b23e2ae64b6f23b82901e2206aab36b671e360ebd414899dab51bbb60134bbe6ad8dcc70b995d9dc50"
//            ],
//            "rtmr0": "b90abd43736381b12fc9b038924c73e31c8371674905e7fcb7941d69fe59d30eda3adb9e41b878151e756fb05ad13d14",
//            "rtmr1": "a53c98b16f0de470338e7f072d9c5fcef6171327ec6c78b842e637251b1de6e37354c47fb68de27ef14bb67caf288d9b",
//            "rtmr2": "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
//            "rtmr3": "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
//            "enforce_tcb_upto_date": false
//        },
//        "policy_ids": [
//            "37965f5f-ccaf-4cdc-a356-a8ed5268a5bf",
//            "9846bf40-e380-4842-ae15-1b60996d1190"
//        ]
//      }
//    }

// ---

// swagger:operation DELETE /key-transfer-policies/{id} KeyTransferPolicies DeleteKeyTransferPolicy
// ---
//
// description: |
//   Deletes a key transfer policy.
// x-permissions: keys-transfer-policies:delete
// security:
//  - bearerAuth: []
// parameters:
// - name: id
//   description: Unique ID of the key transfer policy.
//   in: path
//   required: true
//   type: string
//   format: uuid
// responses:
//   '204':
//     description: Successfully deleted the key transfer policy.
//   '404':
//     description: KeyTransferPolicy record not found
//   '500':
//     description: Internal server error
// x-sample-call-endpoint: https://kbs.com:9443/kbs/v1/key-transfer-policies/75d34bf4-80fb-4ca5-8602-a8d82e56b30d

// ---

// swagger:operation GET /key-transfer-policies KeyTransferPolicies SearchKeyTransferPolicies
// ---
//
// description: |
//   Searches for key transfer policies.
//   Returns - The collection of serialized KeyTransferPolicy Go struct objects.
// x-permissions: keys-transfer-policies:search
// security:
//  - bearerAuth: []
// produces:
//  - application/json
// parameters:
// - name: Accept
//   description: Accept header
//   in: header
//   type: string
//   required: true
//   enum:
//     - application/json
// responses:
//   '200':
//     description: Successfully retrieved the key transfer policies.
//     content:
//       application/json
//     schema:
//       $ref: "#/definitions/KeyTransferPolicies"
//   '400':
//     description: Invalid values for request params
//   '415':
//     description: Invalid Accept Header in Request
//   '500':
//     description: Internal server error
//
// x-sample-call-endpoint: https://kbs.com:9443/kbs/v1/key-transfer-policies
// x-sample-call-output: |
//  [
//    {
//      "id": "d0c3f191-80f9-408f-a690-0dde00ba65ac",
//      "created_at": "2021-08-20T06:30:35.085644391Z",
//      "attestation_type": [
//          "SGX"
//      ],
//      "sgx": {
//        "attributes": {
//            "mr_signer": [
//                "cd171c56941c6ce49690b455f691d9c8a04c2e43e0a4d30f752fa5285c7ee57f"
//            ],
//            "isv_prod_id": [
//                12
//            ],
//            "isv_ext_prod_id": [
//                "00000000000000000000000000000000"
//            ],
//            "mr_enclave": [
//                "01c60b9617b2f96e53cb75ef01e0dccea3afc7b7992697eabb8f714b2ccd1953"
//            ],
//            "config_svn": 0,
//            "isv_svn": 1,
//            "config_id": [
//                "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
//            ],
//            "client_permissions": [
//                "nginx",
//                "USA"
//            ],
//            "enforce_tcb_upto_date": false
//        },
//        "policy_ids": [
//            "37965f5f-ccaf-4cdc-a356-a8ed5268a5bf",
//            "9846bf40-e380-4842-ae15-1b60996d1190"
//        ]
//      }
//    },
//    {
//      "id": "cf9adfcf-4bfa-4653-b9b8-2b94beca768f",
//      "created_at": "2021-08-20T05:51:39.588320016Z",
//      "attestation_type": [
//          "TDX"
//      ],
//      "tdx": {
//        "attributes": {
//            "mr_signer_seam": [
//                "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
//            ],
//            "mr_seam": [
//                "0f3b72d0f9606086d6a7800e7d50b82fa6cb5ec64c7210353a0696c1eef343679bf5b9e8ec0bf58ab3fce10f2c166ebe"
//            ],
//            "seam_svn": 0,
//            "mrtd": [
//                "cf656414fc0f49b23e2ae64b6f23b82901e2206aab36b671e360ebd414899dab51bbb60134bbe6ad8dcc70b995d9dc50"
//            ],
//            "rtmr0": "b90abd43736381b12fc9b038924c73e31c8371674905e7fcb7941d69fe59d30eda3adb9e41b878151e756fb05ad13d14",
//            "rtmr1": "a53c98b16f0de470338e7f072d9c5fcef6171327ec6c78b842e637251b1de6e37354c47fb68de27ef14bb67caf288d9b",
//            "rtmr2": "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
//            "rtmr3": "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
//            "enforce_tcb_upto_date": false
//        },
//        "policy_ids": [
//            "37965f5f-ccaf-4cdc-a356-a8ed5268a5bf",
//            "9846bf40-e380-4842-ae15-1b60996d1190"
//        ]
//      }
//    }
//  ]
