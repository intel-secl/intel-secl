GITCOMMIT := $(shell git describe --always)
GITCOMMITDATE := $(shell git log -1 --date=short --pretty=format:%cd)
VERSION := "v5.0.0"
BUILDDATE := $(shell TZ=UTC date +%Y-%m-%dT%H:%M:%S%z)
PROXY_EXISTS := $(shell if [[ "${https_proxy}" || "${http_proxy}" ]]; then echo 1; else echo 0; fi)
DOCKER_PROXY_FLAGS := ""
ifeq ($(PROXY_EXISTS),1)
	DOCKER_PROXY_FLAGS = --build-arg http_proxy=${http_proxy} --build-arg https_proxy=${https_proxy}
else
	undefine DOCKER_PROXY_FLAGS
endif

TARGETS = cms kbs ihub hvs authservice wpm
K8S_TARGETS = cms kbs ihub hvs authservice aas-manager

$(TARGETS):
	cd cmd/$@ && env GOOS=linux GOSUMDB=off GOPROXY=direct go mod tidy && env GOOS=linux GOSUMDB=off GOPROXY=direct \
		go build -ldflags "-X github.com/intel-secl/intel-secl/v5/pkg/$@/version.BuildDate=$(BUILDDATE) -X github.com/intel-secl/intel-secl/v5/pkg/$@/version.Version=$(VERSION) -X github.com/intel-secl/intel-secl/v5/pkg/$@/version.GitHash=$(GITCOMMIT)" -o $@

%-pre-installer: %
	mkdir -p installer
	cp -r build/linux/$*/* installer/
	cd pkg/lib/common/upgrades && env GOOS=linux GOSUMDB=off GOPROXY=direct go mod tidy && env GOOS=linux GOSUMDB=off GOPROXY=direct go build -o config-upgrade
	cp pkg/lib/common/upgrades/config-upgrade installer/
	cp pkg/lib/common/upgrades/*.sh installer/
	cp -a upgrades/manifest/ installer/
	cp -a upgrades/$*/* installer/
	if [ -d "./installer/db" ]; then \
	     rm -rf ./installer/db ;\
	     cd ./upgrades/$*/db && make all && cd - ;\
	     mkdir -p ./installer/database && cp -a ./upgrades/$*/db/out/* ./installer/database/ ;\
	fi
	mv installer/build/* installer/
	chmod +x installer/*.sh
	cp cmd/$*/$* installer/$*

%-installer: %-pre-installer %
	makeself installer deployments/installer/$*-$(VERSION).bin "$* $(VERSION)" ./install.sh
	rm -rf installer

%-docker: %
	docker build ${DOCKER_PROXY_FLAGS} -f build/image/Dockerfile-$* -t isecl/$*:$(VERSION) .

hvs-docker: hvs
	cd ./upgrades/hvs/db && make all && cd -
	docker build ${DOCKER_PROXY_FLAGS} -f build/image/Dockerfile-hvs -t isecl/hvs:$(VERSION) .

%-swagger:
	env GOOS=linux GOSUMDB=off GOPROXY=direct go mod tidy
	mkdir -p docs/swagger
	swagger generate spec -w ./docs/shared/$* -o ./docs/swagger/$*-openapi.yml
	swagger validate ./docs/swagger/$*-openapi.yml

installer: clean $(patsubst %, %-installer, $(TARGETS)) aas-manager

docker: $(patsubst %, %-docker, $(K8S_TARGETS))

%-oci-archive: %-docker
	skopeo copy docker-daemon:isecl/$*:$(VERSION) oci-archive:deployments/container-archive/oci/$*-$(VERSION)-$(GITCOMMIT).tar:$(VERSION)

populate-users:
	cd tools/aas-manager && env GOOS=linux GOSUMDB=off GOPROXY=direct go build -o populate-users

aas-manager: populate-users
	cp tools/aas-manager/populate-users deployments/installer/populate-users.sh
	cp build/linux/authservice/install_pgdb.sh deployments/installer/install_pgdb.sh
	cp build/linux/authservice/create_db.sh deployments/installer/create_db.sh
	chmod +x deployments/installer/install_pgdb.sh
	chmod +x deployments/installer/create_db.sh

download-eca:
	rm -rf build/linux/hvs/external-eca.pem
	mkdir -p certs/
	wget https://download.microsoft.com/download/D/6/5/D65270B2-EAFD-43FD-B9BA-F65CA00B153E/TrustedTpm.cab -O certs/TrustedTpm.cab
	cabextract certs/TrustedTpm.cab -d certs
	wget https://tsci.intel.com/content/OnDieCA/certs/TGL_00002003_OnDie_CA.cer -O certs/TGL_00002003_OnDie_CA.cer
	find certs/ \( -name '*.der' -or -name '*.crt' -or -name '*.cer' \) | sed 's| |\\ |g' | xargs -L1 openssl x509 -inform DER -outform PEM -in >> build/linux/hvs/external-eca.pem 2> /dev/null || true
	rm -rf certs

test:
	env GOOS=linux GOSUMDB=off GOPROXY=direct go mod tidy
	go test ./... -coverprofile cover.out
	go tool cover -func cover.out
	go tool cover -html=cover.out -o cover.html

authservice-k8s: authservice-oci-archive aas-manager
	cp -r build/k8s/aas deployments/k8s/
	cp tools/aas-manager/populate-users deployments/k8s/aas/populate-users
	cp tools/aas-manager/populate-users.env deployments/k8s/aas/populate-users.env
k8s: $(patsubst %, %-k8s, $(K8S_TARGETS))

%-k8s:  %-oci-archive
	if [ -d "build/k8s/$*" ]; then \
		cp -r build/k8s/$* deployments/k8s/ ;\
	fi
	cp tools/download-tls-certs.sh deployments/k8s/

all: clean installer test k8s

clean:
	rm -f cover.*
	rm -rf deployments/installer/*.bin
	rm -rf deployments/container-archive/docker/*.tar
	rm -rf deployments/container-archive/oci/*.tar

.PHONY: installer test all clean aas-manager kbs
