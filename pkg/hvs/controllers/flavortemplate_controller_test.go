/*
 * Copyright (C) 2021 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */

package controllers_test

import (
	"encoding/json"
	"github.com/gorilla/mux"
	"github.com/intel-secl/intel-secl/v5/pkg/hvs/controllers"
	"github.com/intel-secl/intel-secl/v5/pkg/hvs/domain/mocks"
	hvsRoutes "github.com/intel-secl/intel-secl/v5/pkg/hvs/router"
	consts "github.com/intel-secl/intel-secl/v5/pkg/lib/common/constants"
	"github.com/intel-secl/intel-secl/v5/pkg/model/hvs"
	"strings"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"net/http"
	"net/http/httptest"
)

var _ = Describe("FlavorTemplateController", func() {
	var router *mux.Router
	var w *httptest.ResponseRecorder
	var flavorTemplateStore *mocks.MockFlavorTemplateStore
	var flavorGroupStore *mocks.MockFlavorgroupStore
	var flavorTemplateController *controllers.FlavorTemplateController
	BeforeEach(func() {
		router = mux.NewRouter()
		flavorTemplateStore = mocks.NewFakeFlavorTemplateStore()
		flavorGroupStore = mocks.NewFakeFlavorgroupStore()

		flavorTemplateController = controllers.NewFlavorTemplateController(flavorTemplateStore, flavorGroupStore,
			"../../../build/linux/hvs/schema/common.schema.json", "../../../build/linux/hvs/schema/flavor-template.json")
	})

	// Specs for HTTP Post to "/flavor-templates"
	Describe("Post a new FlavorTemplate", func() {
		Context("Provide a valid FlavorTemplate data", func() {
			It("Should create a new Flavortemplate and get HTTP Status: 201", func() {
				router.Handle("/flavor-templates", hvsRoutes.ErrorHandler(hvsRoutes.JsonResponseHandler(flavorTemplateController.Create))).Methods(http.MethodPost)
				flavorTemplateJson := `{
                   "flavor_template":{
						"label": "test-uefi",
						"condition": [
							"//host_info/vendor='Linux'",
							"//host_info/tpm_version='2.0'",
							"//host_info/uefi_enabled='true'",
							"//host_info/suefi_enabled='true'"
						],
						"flavor_parts": {
							"PLATFORM": {
								"meta": {
									"tpm_version": "2.0",
									"uefi_enabled": true,
									"vendor": "Linux"
								},
								"pcr_rules": [
									{
										"pcr": {
											"index": 0,
											"bank": ["SHA384", "SHA256", "SHA1"]
										},
										"pcr_matches": true,
										"eventlog_equals": {}
									}
								]
							},
							"OS": {
								"meta": {
									"tpm_version": "2.0",
									"uefi_enabled": true,
									"vendor": "Linux"
								},
								"pcr_rules": [
									{
										"pcr": {
											"index": 7,
											"bank": ["SHA384", "SHA256", "SHA1"]
										},
										"pcr_matches": true,
										"eventlog_includes": [
											"shim",
											"db",
											"kek",
											"vmlinuz"
										]
									}
								]
							}
						}
					},
					"flavorgroup_names":["hvs_flavorgroup_test1"]
                }`

				req, err := http.NewRequest(
					http.MethodPost,
					"/flavor-templates",
					strings.NewReader(flavorTemplateJson),
				)
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				req.Header.Set("Content-Type", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusCreated))
			})
		})

		Context("Provide a valid FlavorTemplate data with id", func() {
			It("Should create a new Flavortemplate and get HTTP Status: 201", func() {
				router.Handle("/flavor-templates", hvsRoutes.ErrorHandler(hvsRoutes.JsonResponseHandler(flavorTemplateController.Create))).Methods(http.MethodPost)
				flavorTemplateJson := `{
				   "flavor_template":{
					  "id":"5226d7f1-8105-4f98-9fe2-82220044b514",
					  "label":"test-uefi",
					  "condition":[
						 "//host_info/vendor='Linux'",
						 "//host_info/tpm_version='2.0'",
						 "//host_info/uefi_enabled='true'",
						 "//host_info/suefi_enabled='true'"
					  ],
					  "flavor_parts":{
						 "PLATFORM":{
							"meta":{
							   "tpm_version":"2.0",
							   "uefi_enabled":true,
							   "vendor":"Linux"
							},
							"pcr_rules":[
							   {
								  "pcr":{
									 "index":0,
									 "bank":[
										"SHA384",
										"SHA256",
										"SHA1"
									 ]
								  },
								  "pcr_matches":true,
								  "eventlog_equals":{
									 
								  }
							   }
							]
						 },
						 "OS":{
							"meta":{
							   "tpm_version":"2.0",
							   "uefi_enabled":true,
							   "vendor":"Linux"
							},
							"pcr_rules":[
							   {
								  "pcr":{
									 "index":7,
									 "bank":[
										"SHA384",
										"SHA256",
										"SHA1"
									 ]
								  },
								  "pcr_matches":true,
								  "eventlog_includes":[
									 "shim",
									 "db",
									 "kek",
									 "vmlinuz"
								  ]
							   }
							]
						 }
					  }
				   },
				   "flavorgroup_names":[
					  "hvs_flavorgroup_test1"
				   ]
				}`

				req, err := http.NewRequest(
					http.MethodPost,
					"/flavor-templates",
					strings.NewReader(flavorTemplateJson),
				)
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				req.Header.Set("Content-Type", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusCreated))
			})
		})

		Context("Provide a FlavorTemplate data that contains invalid field key, to validate against schema", func() {
			It("Should get HTTP Status: 400", func() {
				router.Handle("/flavor-templates", hvsRoutes.ErrorHandler(hvsRoutes.JsonResponseHandler(flavorTemplateController.Create))).Methods(http.MethodPost)
				flavorgroupJson := `{
                   "flavor_template": {
						"label": "test-uefi",
						"condition": [
							"//host_info/vendor='Linux'",
							"//host_info/tpm_version='2.0'",
							"//host_info/uefi_enabled='true'",
							"//host_info/suefi_enabled='true'"
						],
						"flavor_parts_new": {
							"PLATFORM": {
								"meta": {
									"tpm_version": "2.0",
									"tboot_installed": true
								},
								"pcr_rules": [
									{
										"pcr": {
											"index": 0,
											"bank": ["SHA384", "SHA256", "SHA1"]
										},
										"pcr_matches": true
									}
								]
							}
						}
					},
					"flavorgroup_names":["hvs_flavorgroup_test1"]
				}`

				req, err := http.NewRequest(
					http.MethodPost,
					"/flavor-templates",
					strings.NewReader(flavorgroupJson),
				)
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				req.Header.Set("Content-Type", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(400))
			})
		})

		Context("Provide a FlavorTemplate data that contains invalid fileds, to validate against schema", func() {
			It("Should get HTTP Status: 400", func() {
				router.Handle("/flavor-templates", hvsRoutes.ErrorHandler(hvsRoutes.JsonResponseHandler(flavorTemplateController.Create))).Methods(http.MethodPost)
				flavorgroupJson := `{
                   "flavor_template": {
						"label": "",
						"condition": [
							"//host_info/vendor='Linux'",
							"//host_info/tpm_version='2.0'",
							"//host_info/uefi_enabled='true'",
							"//host_info/suefi_enabled='true'"
						],
						"flavor_parts": {
							"PLATFORM": {
								"meta": {
									"tpm_version": "2.0",
									"tboot_installed": true
								},
								"pcr_rules": [
									{
										"pcr": {
											"index": 0,
											"bank": ["SHA384", "SHA256", "SHA1"]
										},
										"pcr_matches": true
									}
								]
							}
						}
					},
					"flavorgroup_names":["hvs_flavorgroup_test1"]
				}`

				req, err := http.NewRequest(
					http.MethodPost,
					"/flavor-templates",
					strings.NewReader(flavorgroupJson),
				)
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				req.Header.Set("Content-Type", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(400))
			})
		})

		Context("Provide a empty data that should give bad request error", func() {
			It("Should get HTTP Status: 400", func() {
				router.Handle("/flavor-templates", hvsRoutes.ErrorHandler(hvsRoutes.JsonResponseHandler(flavorTemplateController.Create))).Methods(http.MethodPost)
				req, err := http.NewRequest(
					http.MethodPost,
					"/flavor-templates",
					strings.NewReader(""),
				)
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				req.Header.Set("Content-Type", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(400))
			})
		})

		Context("Provide a valid FlavorTemplate data without ACCEPT header", func() {
			It("Should give HTTP Status: 415", func() {
				router.Handle("/flavor-templates", hvsRoutes.ErrorHandler(hvsRoutes.JsonResponseHandler(flavorTemplateController.Create))).Methods(http.MethodPost)
				flavorTemplateJson := `{
                   "flavor_template": {
						"label": "default-uefi",
						"condition": [
							"//host_info/vendor='Linux'",
							"//host_info/tpm_version='2.0'",
							"//host_info/uefi_enabled='true'",
							"//host_info/suefi_enabled='true'"
						],
						"flavor_parts": {
							"PLATFORM": {
								"meta": {
									"tpm_version": "2.0",
									"uefi_enabled": true,
									"vendor": "Linux"
								},
								"pcr_rules": [
									{
										"pcr": {
											"index": 0,
											"bank": ["SHA384", "SHA256", "SHA1"]
										},
										"pcr_matches": true,
										"eventlog_equals": {}
									}
								]
							},
							"OS": {
								"meta": {
									"tpm_version": "2.0",
									"uefi_enabled": true,
									"vendor": "Linux"
								},
								"pcr_rules": [
									{
										"pcr": {
											"index": 7,
											"bank": ["SHA384", "SHA256", "SHA1"]
										},
										"pcr_matches": true,
										"eventlog_includes": [
											"shim",
											"db",
											"kek",
											"vmlinuz"
										]
									}
								]
							}
						}
					},
					"flavorgroup_names":["hvs_flavorgroup_test1"]
				}`

				req, err := http.NewRequest(
					http.MethodPost,
					"/flavor-templates",
					strings.NewReader(flavorTemplateJson),
				)
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Content-Type", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusUnsupportedMediaType))
			})
		})

		Context("Provide a valid FlavorTemplate data without Content-Type header", func() {
			It("Should give HTTP Status: 415", func() {
				router.Handle("/flavor-templates", hvsRoutes.ErrorHandler(hvsRoutes.JsonResponseHandler(flavorTemplateController.Create))).Methods(http.MethodPost)
				flavorTemplateJson := `{
                   "flavor_template": {
						"label": "default-uefi",
						"condition": [
							"//host_info/vendor='Linux'",
							"//host_info/tpm_version='2.0'",
							"//host_info/uefi_enabled='true'",
							"//host_info/suefi_enabled='true'"
						],
						"flavor_parts": {
							"PLATFORM": {
								"meta": {
									"tpm_version": "2.0",
									"uefi_enabled": true,
									"vendor": "Linux"
								},
								"pcr_rules": [
									{
										"pcr": {
											"index": 0,
											"bank": ["SHA384", "SHA256", "SHA1"]
										},
										"pcr_matches": true,
										"eventlog_equals": {}
									}
								]
							},
							"OS": {
								"meta": {
									"tpm_version": "2.0",
									"uefi_enabled": true,
									"vendor": "Linux"
								},
								"pcr_rules": [
									{
										"pcr": {
											"index": 7,
											"bank": ["SHA384", "SHA256", "SHA1"]
										},
										"pcr_matches": true,
										"eventlog_includes": [
											"shim",
											"db",
											"kek",
											"vmlinuz"
										]
									}
								]
							}
						}
					},
					"flavorgroup_names":["hvs_flavorgroup_test1"]
				}`

				req, err := http.NewRequest(
					http.MethodPost,
					"/flavor-templates",
					strings.NewReader(flavorTemplateJson),
				)
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusUnsupportedMediaType))
			})
		})

		Context("Provide a valid FlavorTemplate data with invalid CONTENT header", func() {
			It("Should give HTTP Status: 415", func() {
				router.Handle("/flavor-templates", hvsRoutes.ErrorHandler(hvsRoutes.JsonResponseHandler(flavorTemplateController.Create))).Methods(http.MethodPost)
				flavorTemplateJson := `{
                   "flavor_template": {
						"label": "default-uefi",
						"condition": [
							"//host_info/vendor='Linux'",
							"//host_info/tpm_version='2.0'",
							"//host_info/uefi_enabled='true'",
							"//host_info/suefi_enabled='true'"
						],
						"flavor_parts": {
							"PLATFORM": {
								"meta": {
									"tpm_version": "2.0",
									"uefi_enabled": true,
									"vendor": "Linux"
								},
								"pcr_rules": [
									{
										"pcr": {
											"index": 0,
											"bank": ["SHA384", "SHA256", "SHA1"]
										},
										"pcr_matches": true,
										"eventlog_equals": {}
									}
								]
							},
							"OS": {
								"meta": {
									"tpm_version": "2.0",
									"uefi_enabled": true,
									"vendor": "Linux"
								},
								"pcr_rules": [
									{
										"pcr": {
											"index": 7,
											"bank": ["SHA384", "SHA256", "SHA1"]
										},
										"pcr_matches": true,
										"eventlog_includes": [
											"shim",
											"db",
											"kek",
											"vmlinuz"
										]
									}
								]
							}
						}
					},
					"flavorgroup_names":["hvs_flavorgroup_test1"]
				}`

				req, err := http.NewRequest(
					http.MethodPost,
					"/flavor-templates",
					strings.NewReader(flavorTemplateJson),
				)
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				req.Header.Set("Content-Type", consts.HTTPMediaTypePlain)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusUnsupportedMediaType))
			})
		})

		Context("Provide a invalid FlavorTemplate data that contains invalid fileds", func() {
			It("Should give HTTP Status: 400", func() {
				router.Handle("/flavor-templates", hvsRoutes.ErrorHandler(hvsRoutes.JsonResponseHandler(flavorTemplateController.Create))).Methods(http.MethodPost)
				flavorTemplateJson := `{
                   "flavor_template": {
						"label": "default-uefi",
						"condition": [
						],
						"flavor_parts": {
							"PLATFORM": {
								"meta": {
									"tpm_version": "2.0",
									"uefi_enabled": true,
									"vendor": "Linux"
								},
								"pcr_rules": [
									{
										"pcr": {
											"index": 0,
											"bank": ["SHA384", "SHA256", "SHA1"]
										},
										"pcr_matches": true,
										"eventlog_equals": {}
									}
								]
							},
							"OS": {
								"meta": {
									"tpm_version": "2.0",
									"uefi_enabled": true,
									"vendor": "Linux"
								},
								"pcr_rules": [
									{
										"pcr": {
											"index": 7,
											"bank": ["SHA384", "SHA256", "SHA1"]
										},
										"pcr_matches": true,
										"eventlog_includes": [
											"shim",
											"db",
											"kek",
											"vmlinuz"
										]
									}
								]
							}
						}
					},
					"flavorgroup_names":["hvs_flavorgroup_test1"]
				}`

				req, err := http.NewRequest(
					http.MethodPost,
					"/flavor-templates",
					strings.NewReader(flavorTemplateJson),
				)
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				req.Header.Set("Content-Type", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusBadRequest))
			})
		})
	})

	// Specs for HTTP Post to "/flavor-template/{flavor-template-id}"
	Describe("Retrieve a FlavorTemplate", func() {
		Context("Retrieve data with valid FlavorTemplate ID", func() {
			It("Should retrieve Flavortemplate data and get HTTP Status: 200", func() {
				router.Handle("/flavor-templates/{ftId}", hvsRoutes.ErrorHandler(hvsRoutes.JsonResponseHandler(flavorTemplateController.Retrieve))).Methods(http.MethodGet)
				req, err := http.NewRequest(http.MethodGet, "/flavor-templates/426912bd-39b0-4daa-ad21-0c6933230b50", nil)
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				req.Header.Set("Content-Type", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusOK))
			})
		})

		Context("Retrieve data with unavailable FlavorTemplate ID", func() {
			It("Should not retrieve Flavortemplate data and get HTTP Status: 404", func() {
				router.Handle("/flavor-templates/{ftId}", hvsRoutes.ErrorHandler(hvsRoutes.JsonResponseHandler(flavorTemplateController.Retrieve))).Methods(http.MethodGet)
				req, err := http.NewRequest(http.MethodGet, "/flavor-templates/73755fda-c910-46be-821f-e8ddeab189e9", nil)
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				req.Header.Set("Content-Type", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusNotFound))
			})
		})

	})

	Describe("Search And Delete Flavor Templates", func() {
		Context("When request header is empty", func() {
			It("Should give HTTP Status: 415", func() {
				router.Handle("/flavor-templates", hvsRoutes.ErrorHandler(hvsRoutes.JsonResponseHandler(flavorTemplateController.Search))).Methods(http.MethodGet)
				req, err := http.NewRequest(http.MethodGet, "/flavor-templates", nil)
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", "")
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusUnsupportedMediaType))

				var fc hvs.FlavorTemplateFlavorgroupCollection
				err = json.Unmarshal(w.Body.Bytes(), &fc)
				Expect(err).To(HaveOccurred())
			})
		})

		Context("When no filter arguments are passed", func() {
			It("All Flavor template records are returned", func() {
				router.Handle("/flavor-templates", hvsRoutes.ErrorHandler(hvsRoutes.JsonResponseHandler(flavorTemplateController.Search))).Methods(http.MethodGet)
				req, err := http.NewRequest(http.MethodGet, "/flavor-templates", nil)
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusOK))

				var ft *[]hvs.FlavorTemplate
				err = json.Unmarshal(w.Body.Bytes(), &ft)
				Expect(err).ToNot(HaveOccurred())
			})
		})

		Context("When id parameter is added in search API", func() {
			It("Flavor template with the given uuid must be returned", func() {
				router.Handle("/flavor-templates/", hvsRoutes.ErrorHandler(hvsRoutes.JsonResponseHandler(flavorTemplateController.Search))).Methods(http.MethodGet)
				req, err := http.NewRequest(http.MethodGet, "/flavor-templates/?id=426912bd-39b0-4daa-ad21-0c6933230b50", nil)
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusOK))

				var ft []hvs.FlavorTemplate
				err = json.Unmarshal(w.Body.Bytes(), &ft)
				Expect(err).ToNot(HaveOccurred())
			})
		})

		Context("When label parameter is added in search API", func() {
			It("Flavor template with the given label must be returned", func() {
				router.Handle("/flavor-templates/", hvsRoutes.ErrorHandler(hvsRoutes.JsonResponseHandler(flavorTemplateController.Search))).Methods(http.MethodGet)
				req, err := http.NewRequest(http.MethodGet, "/flavor-templates/?label=test-uefi", nil)
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusOK))

				var ft []hvs.FlavorTemplate
				err = json.Unmarshal(w.Body.Bytes(), &ft)
				Expect(err).ToNot(HaveOccurred())
			})
		})

		Context("When flavorPartContains parameter is added in search API", func() {
			It("Flavor template with the given flavor part must be returned", func() {
				router.Handle("/flavor-templates/", hvsRoutes.ErrorHandler(hvsRoutes.JsonResponseHandler(flavorTemplateController.Search))).Methods(http.MethodGet)
				req, err := http.NewRequest(http.MethodGet, "/flavor-templates/?flavorPartContains=OS", nil)
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusOK))

				var ft []hvs.FlavorTemplate
				err = json.Unmarshal(w.Body.Bytes(), &ft)
				Expect(err).ToNot(HaveOccurred())
			})
		})

		Context("When conditionContains parameter is added in search API", func() {
			It("Flavor template with the given condition must be returned", func() {
				router.Handle("/flavor-templates/", hvsRoutes.ErrorHandler(hvsRoutes.JsonResponseHandler(flavorTemplateController.Search))).Methods(http.MethodGet)
				req, err := http.NewRequest(http.MethodGet, "/flavor-templates/?conditionContains=//host_info/uefi_enabled='true'", nil)
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusOK))

				var ft []hvs.FlavorTemplate
				err = json.Unmarshal(w.Body.Bytes(), &ft)
				Expect(err).ToNot(HaveOccurred())
			})
		})

		Context("When invalid flavorPart parameter is added in search API", func() {
			It("Should give HTTP status:400", func() {
				router.Handle("/flavor-templates/", hvsRoutes.ErrorHandler(hvsRoutes.JsonResponseHandler(flavorTemplateController.Search))).Methods(http.MethodGet)
				req, err := http.NewRequest(http.MethodGet, "/flavor-templates/?flavorPart=OS", nil)
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusBadRequest))

				var ft []hvs.FlavorTemplate
				err = json.Unmarshal(w.Body.Bytes(), &ft)
				Expect(err).To(HaveOccurred())
			})
		})

		Context("Delete a template which is not in the database", func() {
			It("Appropriate error response should be returned", func() {
				router.Handle("/flavor-templates/{ftId}", hvsRoutes.ErrorHandler(hvsRoutes.JsonResponseHandler(flavorTemplateController.Delete))).Methods(http.MethodDelete)
				req, err := http.NewRequest(http.MethodDelete, "/flavor-templates/426912bd-39b0-4daa-ad21-0c6933230b51", nil)
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusNotFound))
			})
		})

		Context("Delete a template which is available in the database", func() {
			It("The template with the given uuid must be deleted", func() {
				router.Handle("/flavor-templates/{ftId}", hvsRoutes.ErrorHandler(hvsRoutes.JsonResponseHandler(flavorTemplateController.Delete))).Methods(http.MethodDelete)
				req, err := http.NewRequest(http.MethodDelete, "/flavor-templates/426912bd-39b0-4daa-ad21-0c6933230b50", nil)
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusNoContent))
			})
		})

		Context("When includeDeleted parameter is added in search API", func() {
			It("All Flavor template records are returned", func() {
				router.Handle("/flavor-templates/", hvsRoutes.ErrorHandler(hvsRoutes.JsonResponseHandler(flavorTemplateController.Search))).Methods(http.MethodGet)
				req, err := http.NewRequest(http.MethodGet, "/flavor-templates/?includeDeleted=true", nil)
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusOK))

				var ft []hvs.FlavorTemplate
				err = json.Unmarshal(w.Body.Bytes(), &ft)
				Expect(err).ToNot(HaveOccurred())
				Expect(len(ft)).To(Equal(1))
			})
		})

		Context("When false value given for includeDeleted parameter", func() {
			It("Only non-deleted flavor template records are returned", func() {
				router.Handle("/flavor-templates/", hvsRoutes.ErrorHandler(hvsRoutes.JsonResponseHandler(flavorTemplateController.Search))).Methods(http.MethodGet)
				req, err := http.NewRequest(http.MethodGet, "/flavor-templates/?includeDeleted=false", nil)
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusOK))

				var ft []hvs.FlavorTemplate
				err = json.Unmarshal(w.Body.Bytes(), &ft)
				Expect(err).ToNot(HaveOccurred())
				Expect(len(ft)).To(Equal(1))
			})
		})

		Context("When invalid includeDeleted parameter is added in search API", func() {
			It("Should give HTTP Status: 400", func() {
				router.Handle("/flavor-templates/", hvsRoutes.ErrorHandler(hvsRoutes.JsonResponseHandler(flavorTemplateController.Search))).Methods(http.MethodGet)
				req, err := http.NewRequest(http.MethodGet, "/flavor-templates/?includeDeleted=000", nil)
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusBadRequest))

				var ft []hvs.FlavorTemplate
				err = json.Unmarshal(w.Body.Bytes(), &ft)
				Expect(err).To(HaveOccurred())
			})
		})

		Context("When invalid id parameter is added in search API", func() {
			It("Should give HTTP Status: 400", func() {
				router.Handle("/flavor-templates/", hvsRoutes.ErrorHandler(hvsRoutes.JsonResponseHandler(flavorTemplateController.Search))).Methods(http.MethodGet)
				req, err := http.NewRequest(http.MethodGet, "/flavor-templates/?id=000", nil)
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusBadRequest))

				var ft []hvs.FlavorTemplate
				err = json.Unmarshal(w.Body.Bytes(), &ft)
				Expect(err).To(HaveOccurred())
			})
		})

	})
})
