/*
* Tool to generate TLS Certificates for both Server and Client to allow
* Mutual TLS Authentication
*
* Derived from https://github.com/driskell/log-courier/blob/master/src/lc-tlscert/lc-tlscert.go
* Copyright 2014 Jason Woods.
*
* Licensed under the Apache License, Version 2.0 (the "License");
* you may not use this file except in compliance with the License.
* You may obtain a copy of the License at
*
* http://www.apache.org/licenses/LICENSE-2.0
*
* Unless required by applicable law or agreed to in writing, software
* distributed under the License is distributed on an "AS IS" BASIS,
* WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
* See the License for the specific language governing permissions and
* limitations under the License.
*
* Derived from Golang src/pkg/crypto/tls/generate_cert.go
* Copyright 2009 The Go Authors. All rights reserved.
* Use of this source code is governed by a BSD-style
* license that can be found in the LICENSE file.
 */

package main

import (
	"bufio"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"strconv"
	"strings"
	"time"
)

func main() {
	input := newInput()
	cert := collectInformation(input)

	fmt.Println("The certificate can now be generated")
	fmt.Println("Press any key to begin generating the self-signed certificate")

	input.wait()

	generateCertificate(cert)
}

func collectInformation(input *input) *x509.Certificate {
	fmt.Println()
	fmt.Println("Specify the certifiate type. This is ether for Server authentication or Client authenticate.")
	fmt.Println()

	UsageType := input.readOption("Type [Server, Client]", []string{"Client", "Server"})

	extKeyUsage := []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
	if UsageType == "Client" {
		extKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
	}

	fmt.Println()
	fmt.Println("Specify the Organization for the certifiate. The Organization can be anything.")
	fmt.Println()

	organization := input.readString("Organization")

	cert := &x509.Certificate{
		Subject: pkix.Name{
			Organization: []string{organization},
		},
		NotBefore:             time.Now(),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           extKeyUsage,
		BasicConstraintsValid: true,

		IsCA: true,
	}

	fmt.Println()
	fmt.Println("Specify the Common Name for the certificate. The common name")
	fmt.Println("can be anything, but is usually set to the server's primary")
	fmt.Println("DNS name. Even if you plan to connect via IP address you")
	fmt.Println("should specify the DNS name here.")
	fmt.Println()

	cert.Subject.CommonName = input.readString("Common name")

	if UsageType == "Server" {
		fmt.Println()
		fmt.Println("The next step is to add any additional DNS names and IP")
		fmt.Println("addresses that clients may use to connect to the server. If")
		fmt.Println("you plan to connect to the server via IP address and not DNS")
		fmt.Println("then you must specify those IP addresses here.")
		fmt.Println("When you are finished, just press enter.")
		fmt.Println()

		var cnt int

		for {
			cnt++

			val := input.readString(fmt.Sprintf("DNS or IP address %d", cnt))
			if val == "" {
				break
			}

			if ip := net.ParseIP(val); ip != nil {
				cert.IPAddresses = append(cert.IPAddresses, ip)
			} else {
				cert.DNSNames = append(cert.DNSNames, val)
			}
		}
	}

	fmt.Println()
	fmt.Println("How long should the certificate be valid for? A year (365")
	fmt.Println("days) is usual but requires the certificate to be regenerated")
	fmt.Println("within a year or the certificate will cease working.")
	fmt.Println()

	cert.NotAfter = cert.NotBefore.Add(time.Duration(input.readNumber("Number of days")) * time.Hour * 24)

	fmt.Println("Common name:", cert.Subject.CommonName)
	fmt.Println("DNS SANs:")

	if len(cert.DNSNames) == 0 {
		fmt.Println("    None")
	} else {
		for _, e := range cert.DNSNames {
			fmt.Println("   ", e)
		}
	}

	fmt.Println("IP SANs:")

	if len(cert.IPAddresses) == 0 {
		fmt.Println("    None")
	} else {
		for _, e := range cert.IPAddresses {
			fmt.Println("   ", e)
		}
	}

	fmt.Println()

	return cert
}

func generateCertificate(cert *x509.Certificate) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		fmt.Println("Failed to generate private key:", err)
		os.Exit(1)
	}

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	cert.SerialNumber, err = rand.Int(rand.Reader, serialNumberLimit)

	if err != nil {
		fmt.Println("Failed to generate serial number:", err)
		os.Exit(1)
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, cert, cert, &priv.PublicKey, priv)
	if err != nil {
		fmt.Println("Failed to create certificate:", err)
		os.Exit(1)
	}

	filename := "client"
	if cert.ExtKeyUsage[0] == x509.ExtKeyUsageServerAuth {
		filename = "server"
	}

	certOut, err := os.Create(filename + ".crt")
	if err != nil {
		fmt.Println("Failed to open file for writing:", err)
		os.Exit(1)
	}

	b := &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: derBytes,
	}
	if err := pem.Encode(certOut, b); err != nil {
		fmt.Println("Failed encode certificate:", err)
		os.Exit(1)
	}

	certOut.Close()

	keyOut, err := os.OpenFile(filename+".key", os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		fmt.Println("failed to open file for writing:", err)
		os.Exit(1)
	}

	b = &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(priv),
	}
	if err := pem.Encode(keyOut, b); err != nil {
		fmt.Println("Failed encode certificate:", err)
		os.Exit(1)
	}

	keyOut.Close()

	fmt.Println()
	fmt.Println("You may inspect the content of the certificate with something like this:")
	fmt.Println()
	fmt.Printf("openssl x509 -in %s.crt -text\n", filename)
	fmt.Println()
}

type input struct {
	buf *bufio.Reader
}

func newInput() *input {
	return &input{buf: bufio.NewReader(os.Stdin)}
}

func (i *input) wait() {
	i.buf.ReadRune()
}

func (i *input) readString(prompt string) string {
	fmt.Printf("%s: ", prompt)

	var line []byte

	for {
		data, prefix, _ := i.buf.ReadLine()
		line = append(line, data...)

		if !prefix {
			break
		}
	}

	return string(line)
}

func (i *input) readOption(prompt string, options []string) string {
	var selection string
PROMPT:
	for {
		selection = i.readString(prompt)

		for _, option := range options {
			if strings.EqualFold(option, selection) {
				selection = option
				break PROMPT
			}
		}
		fmt.Println("Please enter a valid option")
		continue
	}

	return selection
}

func (i *input) readNumber(prompt string) (num int64) {
	var err error

	for {
		if num, err = strconv.ParseInt(i.readString(prompt), 0, 64); err != nil {
			fmt.Println("Please enter a valid numerical value")
			continue
		}

		break
	}

	return
}
