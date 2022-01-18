# Workload Policy Manager 

`Workload Policy Manager` is used to create the image/container flavors and encrypt them.

## Key features

- create VM image flavors and encrypt the images
- create container image flavors and encrypt the images
- unwrap a key from KBS using the user public key


## System Requirements

- RHEL 8.3
- Epel 8 Repo
- Proxy settings if applicable

## Software requirements

- git
- makeself
- `go` version 1.16.7

# Step-By-Step Build Instructions

## Install required shell commands

### Install tools from `yum`

```shell
sudo yum install -y git wget makeself
```

### Install `go` version >= `go1.12.2` & <= `go1.16.7`
The `Workload Policy Manager` requires Go version 1.16.7 that has support for `go modules`. The build was validated with the latest version 1.16.7 of `go`. It is recommended that you use 1.16.7 version of `go`. You can use the following to install `go`.
```shell
wget https://dl.google.com/go/go1.16.7.linux-amd64.tar.gz
tar -xzf go1.16.7.linux-amd64.tar.gz
sudo mv go /usr/local
export GOROOT=/usr/local/go
export PATH=$GOPATH/bin:$GOROOT/bin:$PATH
```

## Build Workload Policy Manager (WPM)

- Git clone the WPM
- Run scripts to build the WPM

### Build full installer

Supports the following use cases:
- Container confidentiality using skopeo and cri-o


```shell
git clone https://github.com/intel-secl/intel-secl.git
cd intel-secl
make wpm-installer
```

# Third Party Dependencies

## WPM

### Direct dependencies

| Name         | Repo URL                    | Minimum Version Required           |
| -------------| --------------------------- | :--------------------------------: |
| uuid         | github.com/google/uuid      | v1.1.1                             |
| logrus       | github.com/sirupsen/logrus  | v1.4.2                             |
| testify      | github.com/stretchr/testify | v1.3.0                             |
| crypto       | golang.org/x/crypto         | v0.0.0-20190219172222-a4c6cb3142f2 |
| yaml.v2      | gopkg.in/yaml.v2            | v2.2.2                             |


### Indirect Dependencies

| Repo URL                          | Minimum version required           |
| ----------------------------------| :--------------------------------: |
| github.com/Gurpartap/logrus-stack | v0.0.0-20170710170904-89c00d8a28f4 |
| github.com/facebookgo/stack       | v0.0.0-20160209184415-751773369052 |

*Note: All dependencies are listed in go.mod*

# Links

https://intel-secl.github.io/docs/