SHELL := /bin/bash
GITCOMMIT := $(shell git describe --always)
GITCOMMITDATE := $(shell git log -1 --date=short --pretty=format:%cd)
VERSION := "v3.6.1"
BUILDDATE := $(shell TZ=UTC date +%Y-%m-%dT%H:%M:%S%z)
PROXY_EXISTS := $(shell if [[ "${https_proxy}" || "${http_proxy}" ]]; then echo 1; else echo 0; fi)
DOCKER_PROXY_FLAGS := ""
ifeq ($(PROXY_EXISTS),1)
	DOCKER_PROXY_FLAGS = --build-arg http_proxy=${http_proxy} --build-arg https_proxy=${https_proxy}
endif

TARGETS = cms kbs ihub hvs authservice wpm
K8S_TARGETS = cms kbs ihub hvs authservice

$(TARGETS):
	cd cmd/$@ && env GOOS=linux GOSUMDB=off \
		go build -ldflags "-X github.com/intel-secl/intel-secl/v3/pkg/$@/version.BuildDate=$(BUILDDATE) -X github.com/intel-secl/intel-secl/v3/pkg/$@/version.Version=$(VERSION) -X github.com/intel-secl/intel-secl/v3/pkg/$@/version.GitHash=$(GITCOMMIT)" -o $@

kbs:
	mkdir -p installer
	cp /usr/local/lib/libkmip.so.0.2 installer/libkmip.so.0.2
	cd cmd/kbs && env CGO_CFLAGS_ALLOW="-f.*" GOOS=linux GOSUMDB=off \
		go build -gcflags=all="-N -l" \
		-ldflags "-X github.com/intel-secl/intel-secl/v3/pkg/kbs/version.BuildDate=$(BUILDDATE) -X github.com/intel-secl/intel-secl/v3/pkg/kbs/version.Version=$(VERSION) -X github.com/intel-secl/intel-secl/v3/pkg/kbs/version.GitHash=$(GITCOMMIT)" -o kbs

%-installer: %
	mkdir -p installer
	cp build/linux/$*/* installer/
	cd pkg/lib/common/upgrades && env GOOS=linux GOSUMDB=off go build -o config-upgrade
	cp pkg/lib/common/upgrades/config-upgrade installer/
	cp pkg/lib/common/upgrades/*.sh installer/
	cp -a upgrades/manifest/ installer/
	cp -a upgrades/$*/* installer/
	mv installer/build/* installer/
	chmod +x installer/*.sh
	cp cmd/$*/$* installer/$*
	makeself installer deployments/installer/$*-$(VERSION).bin "$* $(VERSION)" ./install.sh
	rm -rf installer

%-docker: %
ifeq ($(PROXY_EXISTS),1)
	docker build ${DOCKER_PROXY_FLAGS} -f build/image/Dockerfile-$* -t isecl/$*:$(VERSION) .
else
	docker build -f build/image/Dockerfile-$* -t isecl/$*:$(VERSION) .
endif

%-swagger:
	mkdir -p docs/swagger
	swagger generate spec -w ./docs/shared/$* -o ./docs/swagger/$*-openapi.yml
	swagger validate ./docs/swagger/$*-openapi.yml

installer: clean $(patsubst %, %-installer, $(TARGETS)) aas-manager

docker: $(patsubst %, %-docker, $(K8S_TARGETS))

%-oci-archive: %-docker
	skopeo copy docker-daemon:isecl/$*:$(VERSION) oci-archive:deployments/container-archive/oci/$*-$(VERSION)-$(GITCOMMIT).tar:$(VERSION)

kbs-docker: kbs
	cp /usr/local/lib/libkmip.so.0.2 build/image/
	docker build . -f build/image/Dockerfile-kbs -t isecl/kbs:$(VERSION)
	docker save isecl/kbs:$(VERSION) > deployments/container-archive/docker/docker-kbs-$(VERSION)-$(GITCOMMIT).tar

aas-manager:
	cd tools/aas-manager && env GOOS=linux GOSUMDB=off go build -o populate-users
	cp tools/aas-manager/populate-users deployments/installer/populate-users.sh
	cp build/linux/authservice/install_pgdb.sh deployments/installer/install_pgdb.sh
	cp build/linux/authservice/create_db.sh deployments/installer/create_db.sh
	chmod +x deployments/installer/install_pgdb.sh
	chmod +x deployments/installer/create_db.sh

wpm-docker-installer: wpm
	mkdir -p installer
	cp build/linux/wpm/* installer/
	cd pkg/lib/common/upgrades && env GOOS=linux GOSUMDB=off go build -o config-upgrade
	cp pkg/lib/common/upgrades/config-upgrade installer/
	cp pkg/lib/common/upgrades/*.sh installer/
	cp -a upgrades/manifest/ installer/
	cp -a upgrades/wpm/* installer/
	mv installer/build/* installer/
	chmod +x installer/*.sh
	installer/build-secure-docker-daemon.sh
	cp -rf secure-docker-daemon/out installer/docker-daemon
	rm -rf secure-docker-daemon
	cp cmd/wpm/wpm installer/wpm
	makeself installer deployments/installer/wpm-$(VERSION).bin "wpm $(VERSION)" ./install.sh
	rm -rf installer

download-eca:
	rm -rf build/linux/hvs/external-eca.pem
	mkdir -p certs/
	wget https://download.microsoft.com/download/D/6/5/D65270B2-EAFD-43FD-B9BA-F65CA00B153E/TrustedTpm.cab -O certs/TrustedTpm.cab
	cabextract certs/TrustedTpm.cab -d certs
	find certs/ \( -name '*.der' -or -name '*.crt' -or -name '*.cer' \) | sed 's| |\\ |g' | xargs -L1 openssl x509 -inform DER -outform PEM -in >> build/linux/hvs/external-eca.pem 2> /dev/null || true
	rm -rf certs

test:
	CGO_LDFLAGS="-Wl,-rpath -Wl,/usr/local/lib" CGO_CFLAGS_ALLOW="-f.*" go test ./... -coverprofile cover.out
	go tool cover -func cover.out
	go tool cover -html=cover.out -o cover.html

authservice-k8s: authservice-oci-archive aas-manager
	cp -r build/k8s/aas deployments/k8s/
	cp tools/aas-manager/populate-users deployments/k8s/aas/populate-users
	cp tools/aas-manager/populate-users.env deployments/k8s/aas/populate-users.env
	 
k8s: $(patsubst %, %-k8s, $(K8S_TARGETS))

%-k8s:  %-oci-archive
	cp -r build/k8s/$* deployments/k8s/

all: clean installer test k8s

clean:
	rm -f cover.*
	rm -rf deployments/installer/*.bin
	rm -rf deployments/container-archive/docker/*.tar
	rm -rf deployments/container-archive/oci/*.tar

.PHONY: installer test all clean kbs-docker aas-manager kbs wpm-docker-installer
