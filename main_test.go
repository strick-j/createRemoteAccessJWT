package main

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"regexp"
	"strings"
	"testing"

	"github.com/golang-jwt/jwt/v4"
)

// TestRandSequence calls randSequence with a value of 20
// and checks for a valid response
func TestRandSequence(t *testing.T) {
	want := regexp.MustCompile("^([a-zA-Z]{20})$")
	sequence := randSeq(20)
	if !want.MatchString(sequence) {
		t.Fatalf("randSeq(20) = %q, want match for %#q, nil", sequence, want)
	}
}

// TestCheckTenant_IsCorrectForValidInput calls checkTenant with
// valid inputs
func TestCheckTenant_IsCorrectForValidInput(t *testing.T) {
	var tests = []struct {
		name  string
		input string
		want  string
	}{
		{"ValidID1", "11ed307a252abc12345ab76ae4e1234a", "Valid Tenant Id"},
		{"ValidID2", "12ed305a257abc15645ab76ae4e1234a", "Valid Tenant Id"},
		{"ValidID3", "12ed305a257abc15645ab76ae4e1234A", "Valid Tenant Id"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := checkTenant(tt.input)
			if err != nil {
				t.Fatal(err)
			}
			if got != tt.want {
				t.Errorf("got %s, want %s", got, tt.want)
			}
		})
	}
}

// TestCheckTenant_ErrorsOnInvalidINput calls checkTenant with
// invalid inputs
func TestCheckTenant_ErrorsOnInvalidInput(t *testing.T) {
	var tests = []struct {
		name  string
		input string
	}{
		{"InvalidID1", "11ed307a252abc12345ab76a"},
		{"InvalidID2", "12ed305a257abc15645ab76ae4e1234a1224352"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := checkTenant(tt.input)
			if err == nil {
				t.Error("want error for invalid input")
			}
		})
	}
}

// TestCheckRegion calls checkRegion with all valid regions and an invalid region
// and checks for the proper response
func TestCheckRegion(t *testing.T) {
	var tests = []struct {
		name  string
		input string
		want  string
	}{
		{"us", "us", "https://auth.alero.io/auth/realms/serviceaccounts"},
		{"eu", "EU", "https://auth.alero.eu/auth/realms/serviceaccounts"},
		{"canada", "CanAdA", "https://auth.ca.alero.io/auth/realms/serviceaccounts"},
		{"austraila", "austRAila", "https://auth.au.alero.io/auth/realms/serviceaccounts"},
		{"london", "LONDON", "https://auth.uk.alero.io/auth/realms/serviceaccounts"},
		{"india", "india", "https://auth.in.alero.io/auth/realms/serviceaccounts"},
		{"singapore", "singapore", "https://auth.sg.alero.io/auth/realms/serviceaccounts"},
		{"invalid region", "usa", "Invalid Region"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ans, _ := checkRegion(tt.input)
			if ans != tt.want {
				t.Errorf("got %s, want %s", ans, tt.want)
			}
		})
	}
}

// TestReadKeyFile calls readKeyFile
func TestReadKeyFile_ErrorsOnNoFile(t *testing.T) {
	err := readKeyFile("./tests/exmaple.json")
	if err == nil {
		t.Error("want error when no json files are present")
	}
}

// TestReadKeyFile calls readKeyFile
func TestReadKeyFile_ErrorsOnFileFormatIssue(t *testing.T) {
	err := readKeyFile("./tests/invalidSample.json")
	if err == nil {
		t.Error("want error when no json file has wrong format")
	}
}

// TestGenerateJWT_ErrorsOnMissingParameter calls generateJWT with
// missing parameters
func TestGenerateJWT_ErrorsOnMissingParameter(t *testing.T) {
	var tests = []struct {
		name     string
		tenant   string
		aud      string
		jsonfile string
		want     error
	}{
		{"missingPrivateKey", "12ed123a123abc12345ef45ae4e1234a", "https://auth.alero.io/auth/realms/serviceaccounts", "./tests/missingPrivateKey.json", fmt.Errorf("generateJWT: Error - Private Key missing or not found")},
		{"missingServiceAccount", "12ed123a123abc12345ef45ae4e1234a", "https://auth.alero.io/auth/realms/serviceaccounts", "./tests/missingServiceAccount.json", fmt.Errorf("generateJWT: Error - Service Account Id missing or not found")},
		{"missingTenantId", "", "https://auth.alero.io/auth/realms/serviceaccounts", "./tests/validSample.json", fmt.Errorf("generateJWT: Error - Tenant Id missing or not found")},
		{"missingAudience", "12ed123a123abc12345ef45ae4e1234a", "", "./tests/validSample.json", fmt.Errorf("generateJWT: Error - Audience missing or not found")},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := readKeyFile(tt.jsonfile)
			if err != nil {
				t.Fatalf("error with testcase")
			}
			_, err1 := generateJWT(tt.tenant, tt.aud)
			if err1 == nil {
				t.Error("want error when parameter is missing")
			}
		})
	}
}

// TestGenerateJWT_ValidToken calls generateJWT with valid parameters
// and valid public key
func TestGenerateJWT(t *testing.T) {
	err := readKeyFile("./tests/validSample.json")
	if err != nil {
		t.Errorf("failed to read validSample.json")
	}
	tokenString, err1 := generateJWT("12ed123a123abc12345ef45ae4e1234a", "https://auth.alero.io/auth/realms/serviceaccounts")
	if err1 != nil {
		t.Errorf("failed to generate JWT")
	}

	// Parse Public Key
	// Public Key corresponds to Private Key used to sign token
	pemString := strings.TrimSpace("-----BEGIN RSA PUBLIC KEY-----\r\nMIIBCgKCAQEA3ikAtAp21AYJN/UzrW4zPHPRqTb8bxU5axOteXMm3ZzbZJSqvciS\r\nQCcKiZYz+X5yjrE8ywzIDMGCKg2rkJzcDfAkirJ7AZg6NxW5NcdJpI7yAbMhu9YK\r\nQTob9iXJX6ddY63vYK2GwgIj6OIoVsulGSW+ATMJcrU5ifC+UC2cLCysGNWYriWA\r\nbSAc/mn4PacbNExRCMXlLR8+ojRaUrB4Uhq2DLfXhUojAkkaoLDIFVKN0okNU/YD\r\n	qnCfWf3DCTD7douxPUKmfylW0MxTIvCeDI3iJga0lYuYkGGcdv08GZYzp7gQ+wXh\r\nZpqTbHff+jsr75HpCnxIXHRHw5Dty58FowIDAQAB\r\n-----END RSA PUBLIC KEY-----")
	block, _ := pem.Decode([]byte(pemString))
	if block == nil {
		t.Fatalf("failed to parse PEM block containing public key: %v", err)
	}
	pubkey, err := x509.ParsePKCS1PublicKey(block.Bytes)
	if err != nil {
		t.Fatalf("failed to parse public key: %v", err)
	}

	// Parse token
	token, err := jwt.Parse(*tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected method: %s", token.Header["alg"])
		}
		return pubkey, nil
	})
	if err != nil {
		t.Errorf("error: %v", err)
	}

	// Check validity of returned token
	if !token.Valid {
		t.Errorf("want valid token")
	}
}
