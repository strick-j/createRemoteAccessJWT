# createRemoteAccessJWT

## Install and Configure

### Manual
1. `git clone https://github.com/strick-j/createremoteaccessjwt`
2. Build application using GO Build steps below

#### Windows
-  64 Bit AMD: `GOOS=windows GOARCH=amd64 go build -o createremoteaccessjwt64.exe main.go`
-  32 Bit AMD: `GOOS=windows GOARCH=386 go build -o createremoteaccessjwt86.exe main.go`
-  64 Bit ARM: `GOOS=windows GOARCH=arm64 go build -o createremoteaccessjwt64.exe main.go`

#### Mac
-  64 Bit AMD: `GOOS=darwin GOARCH=amd64 go build -o createremoteaccessjwt64 main.go`
-  32 Bit AMD: `GOOS=darwin GOARCH=386 go build -o createremoteaccessjwt86 main.go`
-  64 Bit ARM: `GOOS=darwin GOARCH=arm64 go build -o createremoteaccessjwt64.exe main.go`

#### Linux
-  64 Bit AMD: `GOOS=linux GOARCH=amd64 go build -o createremoteaccessjwt64 main.go`
-  32 Bit AMD: `GOOS=linux GOARCH=386 go build -o createremoteaccessjwt86 main.go`
-  64 Bit ARM: `GOOS=linux GOARCH=arm64 go build -o createremoteaccessjwt86 main.go`

### Run
1. ./createremoteaccessjwt -region=<region> -tenantid=<tenantid>

Note: The json file created when the service account was created needs to be in the folder you are running the application from.