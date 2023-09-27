package main

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"log"
	"math/rand"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/golang-jwt/jwt"
)

func init() {
	rand.New(rand.NewSource(time.Now().UnixNano()))
}

type KeyFile struct {
	ServiceAccountId string `json:"serviceAccountId"`
	PrivateKey       string `json:"privateKey"`
	DiscoveryURL     string `json:"discoveryURL"`
}

var (
	key         *rsa.PrivateKey
	keyFile     KeyFile
	keyFileName string
)

// Generates a random sequency of numbers to utlize for the 'jti' portion of the jwt
func randSeq(n int) string {
	var letters = []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")
	b := make([]rune, n)
	for i := range b {
		b[i] = letters[rand.Intn(len(letters))]
	}
	return string(b)
}

// Checks for Tenant ID and validates if it is 32 charachters
// including lowercase letters and numbers
func checkTenant(tenantid string) (string, error) {
	check := regexp.MustCompile("^([a-z0-9]{32})$")
	if !check.MatchString(strings.ToLower(tenantid)) {
		err := fmt.Errorf("checkTenant: Invalid Tenant ID provided: %v", tenantid)
		msg := "Invalid Tenant Id"
		return msg, err
	}
	msg := "Valid Tenant Id"
	return msg, nil
}

// Checks to make sure a region was provided and is valid.
func checkRegion(region string) (string, error) {
	audurl := map[string]string{
		"us":        "https://auth.alero.io/auth/realms/serviceaccounts",
		"eu":        "https://auth.alero.eu/auth/realms/serviceaccounts",
		"canada":    "https://auth.ca.alero.io/auth/realms/serviceaccounts",
		"austraila": "https://auth.au.alero.io/auth/realms/serviceaccounts",
		"london":    "https://auth.uk.alero.io/auth/realms/serviceaccounts",
		"india":     "https://auth.in.alero.io/auth/realms/serviceaccounts",
		"singapore": "https://auth.sg.alero.io/auth/realms/serviceaccounts",
	}
	var u interface{} = audurl
	audience := u.(map[string]string)[strings.ToLower(region)]
	if len(audience) == 0 {
		err := fmt.Errorf("checkTenant: Invalid region provided: %v. Valid regions are: US, EU, Canada, Austraila, London, India, and Singapore", region)
		msg := "Invalid Region"
		return msg, err
	}
	return audience, nil
}

// Finds the json file in the current directory.
func locateKeyFile() (*string, error) {
	wd, err := os.Getwd()
	if err != nil {
		log.Fatal(err)
	}
	dir, err := os.Open(wd)
	if err != nil {
		log.Fatal(err)
	}
	files, err := dir.Readdir(-1)
	if err != nil {
		log.Fatal(err)
	}
	i := 0
	for _, f := range files {
		if strings.Contains(f.Name(), "json") {
			keyFileName = f.Name()
			i = i + 1
		}
	}
	if i != 1 {
		msg := errors.New("readKeyFile: No JSON file or more than one JSON file detected in current directory. Please remove any files that are not the key file provided by the Remote Access Portal")
		return nil, msg
	}
	return &keyFileName, nil
}

// Reads the file and writes it to the keyFile struct.
func readKeyFile(keyFileName string) error {
	keyFileByte, err := os.ReadFile(keyFileName)
	if err != nil {
		err := fmt.Errorf("readKeyFile: Error opening file: %v", err)
		return err
	}
	err = json.Unmarshal(keyFileByte, &keyFile)
	if err != nil {
		err := fmt.Errorf("readKeyFile: Error unmarshaling json: %v", err)
		return err
	}
	return nil
}

// Creates JWT using claims required by the CyberArk Remote Access service.
// Uses arguments (Tenant ID and Region) as well as certificate to create signed JWT.
func generateJWT(tenantid, audience string) (*string, error) {
	// Validates all required variables are present, returns error if missing
	check := []string{keyFile.PrivateKey, keyFile.ServiceAccountId, tenantid, audience}
	msg := []string{"Private Key", "Sevice Account Id", "Tenant Id", "Audience"}
	for i, c := range check {
		if c == "" {
			err := fmt.Errorf("generateJWT: Error - %v missing or not found", msg[i])
			fmt.Printf("%v", err)
			return nil, err
		}
	}
	// Creates the *rsa.PrivateKey from string extracted from the json file
	pemString := strings.TrimSpace(keyFile.PrivateKey)
	block, _ := pem.Decode([]byte(pemString))
	key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("generateJWT: %v", err)
	}

	s := tenantid + "." + keyFile.ServiceAccountId + ".ExternalServiceAccount"

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		"iss": s,
		"sub": s,
		"aud": audience,
		"iat": time.Now().Unix(),
		"exp": time.Now().Add(time.Duration(5) * time.Minute).Unix(),
		"jti": randSeq(20),
	})

	tokenString, err := token.SignedString(key)
	if err != nil {
		return nil, err
	}

	log.Printf("Token: %v", tokenString)
	return &tokenString, nil
}

func main() {
	var err error
	tenantidPtr := flag.String("tenantid", "", "Tenant ID, e.g. 11ed123a252abc10987ef76ae4e1234d")
	regionPtr := flag.String("region", "", "Service Region: US, EU, Canada, Austraila, London, India, and Singapore")

	flag.Parse()
	if *tenantidPtr == "" || *regionPtr == "" {
		log.Fatalf("Missing Tenant ID or Region. Use -h for help.")
	}
	log.Printf("Attempting to generate jwt using Tenant ID: %q and Region: %q", *tenantidPtr, *regionPtr)

	tenantCheck, err := checkTenant(*tenantidPtr)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("%v", tenantCheck)

	audience, err := checkRegion(*regionPtr)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("Valid region provided. Audience: %v", audience)

	keyFileName, err := locateKeyFile()
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("Remote Access File: %v", *keyFileName)

	err = readKeyFile(*keyFileName)
	if err != nil {
		log.Fatal(err)
	}

	token, err := generateJWT(*tenantidPtr, audience)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("Token: %v", *token)
}
