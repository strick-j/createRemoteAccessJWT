package main

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"log"
	"math/rand"
	"os"
	"strings"
	"time"

	"github.com/golang-jwt/jwt"
)

func init() {
	rand.Seed(time.Now().UnixNano())
}

type KeyFile struct {
	ServiceAccountId string `json:"serviceAccountId"`
	PrivateKey       string `json:"privateKey"`
	DiscoveryURL     string `json:"discoveryURL"`
}

var (
	key         *rsa.PrivateKey
	audience    string
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

// Checks to make sure two arguments are present
// Additionally, validates the second argument region
func checkArguments() {
	if len(os.Args[:]) < 3 {
		log.Print("Execute the program with two parameters (TenantId and Region). E.g. ./createremoteaccessjwt <TenantId> <Region>")
		log.Fatal("Not enough arguments provided. Please provide your tenant id and region as arguments. Valid regions are: US, EU, Canada, Austraila, London, India, and Singapore")
	}
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
	audience = u.(map[string]string)[strings.ToLower(os.Args[2])]
	if len(audience) == 0 {
		log.Fatal("Invalid region provided. Valid regions are: US, EU, Canada, Austraila, London, India, and Singapore")
	}
	log.Printf("Audience: %v", audience)
}

// Finds the json file in the current directory. Reads the file and writes it to the keyFile struct.
func readKeyFile() {
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
		log.Fatal("No JSON file or more than one JSON file detected in current directory. Please remove any files that are not the key file provided by the Remote Access Portal.")
	}
	log.Printf("Remote Access File: %v", keyFileName)

	keyFileByte, err := os.ReadFile(keyFileName)
	if err != nil {
		log.Fatalf("Error opening file: %v", err)
	}
	json.Unmarshal(keyFileByte, &keyFile)
}

// Creates JWT using claims required by the CyberArk Remote Access service. Uses arguments (Tenant ID and Region) as well as certificate to create signed JWT.
func generateJWT() {
	pemString := strings.TrimSpace(keyFile.PrivateKey)
	block, _ := pem.Decode([]byte(pemString))
	key, _ = x509.ParsePKCS1PrivateKey(block.Bytes)

	s := os.Args[1] + "." + keyFile.ServiceAccountId + ".ExternalServiceAccount"

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
		log.Fatal(err)
	}

	log.Printf("Token: %v", tokenString)
}

func main() {
	// Validate that all arguments were passed
	// Returns error if less than 2 arguments were passed
	checkArguments()
	// Attempts to locate file provided when service account user was created
	// If more than one json file is present in working directory an error is returned
	readKeyFile()
	// Utilizes Arguments (Tenant Id and Location) in addtion to json file to create JWT
	// Returns error if the JWT cannot be generated
	generateJWT()
}
