module github.com/intel-secl/intel-secl/v5

require (
	github.com/DATA-DOG/go-sqlmock v1.4.1
	github.com/Waterdrips/jwt-go v3.2.1-0.20200915121943-f6506928b72e+incompatible
	github.com/antchfx/jsonquery v1.1.4
	github.com/beevik/etree v1.1.0
	github.com/containers/ocicrypt v1.1.2
	github.com/davecgh/go-spew v1.1.1
	github.com/gemalto/kmip-go v0.0.6-0.20210426170211-84e83580888d
	github.com/google/uuid v1.2.0
	github.com/gorilla/handlers v1.4.2
	github.com/gorilla/mux v1.7.3
	github.com/hashicorp/golang-lru v0.5.1
	github.com/jinzhu/copier v0.3.0
	github.com/jinzhu/gorm v1.9.16
	github.com/joho/godotenv v1.3.0
	github.com/lib/pq v1.3.0
	github.com/mattermost/xml-roundtrip-validator v0.0.0-20201213122252-bcd7e1b9601e
	github.com/nats-io/jwt/v2 v2.0.2
	github.com/nats-io/nats.go v1.11.0
	github.com/nats-io/nkeys v0.3.0
	github.com/onsi/ginkgo v1.13.0
	github.com/onsi/gomega v1.10.1
	github.com/pkg/errors v0.9.1
	github.com/russellhaering/goxmldsig v1.1.0
	github.com/sirupsen/logrus v1.7.0
	github.com/spf13/viper v1.7.1
	github.com/stretchr/testify v1.6.1
	github.com/vmware/govmomi v0.22.2
	github.com/xeipuuv/gojsonschema v1.2.0
	golang.org/x/crypto v0.0.0-20210322153248-0c34fe9e7dc2
	golang.org/x/sync v0.0.0-20200625203802-6e8e738ad208
	gopkg.in/yaml.v2 v2.4.0
)

replace github.com/vmware/govmomi => github.com/arijit8972/govmomi v0.22.2-0.20210618070400-c203a7ed3d26

go 1.13
