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
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"

	"github.com/jtwatson/mutualtlsconfig"
)

func main() {
	input := newInput()
	cert := collectInformation(input)

	fmt.Println("The certificate can now be generated")
	fmt.Println("Press any key to begin generating the self-signed certificate")

	input.wait()

	if err := generateCertificate(cert); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

func collectInformation(input *input) *mutualtlsconfig.CertificateInformation {
	certInfo := &mutualtlsconfig.CertificateInformation{
		Type: mutualtlsconfig.ServerCertType,
	}

	fmt.Println()
	fmt.Println("Specify the certifiate type. This is ether for Server authentication or Client authenticate.")
	fmt.Println()

	if input.readOption("Type [Server, Client]", []string{"Client", "Server"}) == "Client" {
		certInfo.Type = mutualtlsconfig.ClientCertType
	}

	fmt.Println()
	fmt.Println("Specify the Organization for the certifiate. The Organization can be anything.")
	fmt.Println()

	certInfo.Organization = input.readString("Organization")

	fmt.Println()
	fmt.Println("Specify the Common Name for the certificate. The common name")
	fmt.Println("can be anything, but is usually set to the server's primary")
	fmt.Println("DNS name. Even if you plan to connect via IP address you")
	fmt.Println("should specify the DNS name here.")
	fmt.Println()

	certInfo.CommonName = input.readString("Common name")

	if certInfo.Type == mutualtlsconfig.ServerCertType {
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
				certInfo.IPAddresses = append(certInfo.IPAddresses, ip)
			} else {
				certInfo.DNSNames = append(certInfo.DNSNames, val)
			}
		}
	}

	fmt.Println()
	fmt.Println("How long should the certificate be valid for? A year (365")
	fmt.Println("days) is usual but requires the certificate to be regenerated")
	fmt.Println("within a year or the certificate will cease working.")
	fmt.Println()

	certInfo.Days = int(input.readNumber("Number of days"))

	fmt.Println("Common name:", certInfo.CommonName)
	fmt.Println("DNS SANs:")

	if len(certInfo.DNSNames) == 0 {
		fmt.Println("    None")
	} else {
		for _, e := range certInfo.DNSNames {
			fmt.Println("   ", e)
		}
	}

	fmt.Println("IP SANs:")

	if len(certInfo.IPAddresses) == 0 {
		fmt.Println("    None")
	} else {
		for _, e := range certInfo.IPAddresses {
			fmt.Println("   ", e)
		}
	}

	fmt.Println()

	return certInfo
}

func generateCertificate(certInfo *mutualtlsconfig.CertificateInformation) error {
	cert, key, err := certInfo.Generate()
	if err != nil {
		return err
	}

	filename := "client"
	if certInfo.Type == mutualtlsconfig.ServerCertType {
		filename = "server"
	}

	certOut, err := os.Create(filename + ".crt")
	if err != nil {
		return fmt.Errorf("failed to open certificate file for writing: %w", err)
	}

	if _, err := certOut.Write(cert); err != nil {
		return fmt.Errorf("failed write certificate to file: %w", err)
	}

	if err := certOut.Close(); err != nil {
		return fmt.Errorf("failed closing certificate file: %w", err)
	}

	keyOut, err := os.OpenFile(filename+".key", os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return fmt.Errorf("failed to open key file for writing: %w", err)
	}

	if _, err := keyOut.Write(key); err != nil {
		return fmt.Errorf("failed write key to file: %w", err)
	}

	if err := keyOut.Close(); err != nil {
		return fmt.Errorf("failed closing key file: %w", err)
	}

	fmt.Println()
	fmt.Println("You may inspect the content of the certificate with something like this:")
	fmt.Println()
	fmt.Printf("openssl x509 -in %s.crt -text\n", filename)
	fmt.Println()

	return nil
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
