package mutualtlsconfig

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"time"
)

type CertType x509.ExtKeyUsage

const (
	// ServerCertType indicates the Certificate has x509.ExtKeyUsageServerAuth set
	ServerCertType CertType = CertType(x509.ExtKeyUsageServerAuth)

	// ClientCertType indicates the Certificate has x509.ExtKeyUsageClientAuth set
	ClientCertType CertType = CertType(x509.ExtKeyUsageClientAuth)
)

// CertificateInformation holds required information for generating a Self Signed Certificate
type CertificateInformation struct {
	Begin        time.Time
	CommonName   string
	Days         int
	DNSNames     []string
	IPAddresses  []net.IP
	Organization string
	Type         CertType
}

func (c *CertificateInformation) Generate() (cert, key []byte, err error) {
	var (
		certBuf bytes.Buffer
		keyBuf  bytes.Buffer
	)

	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate private key: %w", err)
	}

	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate serial number: %w", err)
	}

	begin := c.Begin
	if begin.IsZero() {
		begin = time.Now()
	}

	template := &x509.Certificate{
		BasicConstraintsValid: true,
		DNSNames:              c.DNSNames,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsage(c.Type)},
		IPAddresses:           c.IPAddresses,
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		NotAfter:              begin.Add(time.Duration(c.Days) * time.Hour * 24),
		NotBefore:             begin,
		SerialNumber:          serialNumber,
		Subject: pkix.Name{
			CommonName:   c.CommonName,
			Organization: []string{c.Organization},
		},
	}

	certBytes, err := x509.CreateCertificate(rand.Reader, template, template, &priv.PublicKey, priv)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create certificate: %w", err)
	}

	b := &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certBytes,
	}
	if err := pem.Encode(&certBuf, b); err != nil {
		return nil, nil, fmt.Errorf("failed encode certificate: %w", err)
	}

	b = &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(priv),
	}
	if err := pem.Encode(&keyBuf, b); err != nil {
		return nil, nil, fmt.Errorf("failed encode certificate: %w", err)
	}

	return certBuf.Bytes(), keyBuf.Bytes(), nil
}
