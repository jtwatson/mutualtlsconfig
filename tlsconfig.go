/*
Package mutualtlsconfig provides helpers to configure Mutual TLS Authentication
between a Client and Server.
*/
package mutualtlsconfig

import (
	"crypto/tls"
	"crypto/x509"
	"io/ioutil"
	"net"
	"net/http"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/hashicorp/go-version"
)

// TLSConfigurator is a utility to simplify setting up a Client/Server
// using TLS Mutual athentication. The tls.Config's returned will
// validate certificates for both the Client and Server.
type TLSConfigurator struct {
	clientCerts []tls.Certificate
	caCerts     [][]byte
}

// New returns a TLSConfigurator
func New(cert, key []byte, caCerts ...[]byte) (*TLSConfigurator, error) {
	clientCert, err := tls.X509KeyPair(cert, key)
	if err != nil {
		return nil, err
	}

	return &TLSConfigurator{
		clientCerts: []tls.Certificate{clientCert},
		caCerts:     caCerts,
	}, nil
}

// NewFromFile loads from files and returns a TLSConfigurator.
func NewFromFile(cert, key string, caCerts ...string) (*TLSConfigurator, error) {
	return NewFromFS(nil, cert, key, caCerts...)
}

// NewFromFS loads from fs and returns a TLSConfigurator.
func NewFromFS(fs http.FileSystem, cert, key string, caCerts ...string) (*TLSConfigurator, error) {
	certPEM, err := loadBytes(fs, cert)
	if err != nil {
		return nil, err
	}

	keyPEM, err := loadBytes(fs, key)
	if err != nil {
		return nil, err
	}

	caCertSlice := make([][]byte, 0, len(caCerts))

	for _, cert := range caCerts {
		certPEM, err := loadBytes(fs, cert)
		if err != nil {
			return nil, err
		}

		caCertSlice = append(caCertSlice, certPEM)
	}

	return New(certPEM, keyPEM, caCertSlice...)
}

// TLSClientConfig returns a tls.Config which will fully validate the
// server certificate using the provided CaCerts.
func (c *TLSConfigurator) TLSClientConfig() *tls.Config {
	// Setup client
	tlsConfig := &tls.Config{
		RootCAs:      c.loadServerCertPool(),
		Certificates: c.clientCerts,
	}

	if beforeGo114(runtime.Version()) {
		tlsConfig.BuildNameToCertificate()
	}

	return tlsConfig
}

// TLSServerConfig returns a tls.Config which will require and fully
// validate a client certificate using the provided CaCerts with
// option tls.RequireAndVerifyClientCert. The client
// certificate must have x509.ExtKeyUsageClientAuth set.
func (c *TLSConfigurator) TLSServerConfig() *tls.Config {
	// Setup server
	tlsConfig := &tls.Config{
		ClientCAs:    c.loadServerCertPool(),
		Certificates: c.clientCerts,
		ClientAuth:   tls.RequireAndVerifyClientCert,
		NextProtos:   []string{"http/1.1"},
	}

	if beforeGo114(runtime.Version()) {
		tlsConfig.BuildNameToCertificate()
	}

	return tlsConfig
}

// TLSListener wraps the TLSServerConfig around the net.Listener
func (c *TLSConfigurator) TLSListener(ln net.Listener) net.Listener {
	return tls.NewListener(ln, c.TLSServerConfig())
}

// HTTPSClient returns a http.Client with its Transport configured for TLS.
func (c *TLSConfigurator) HTTPSClient() *http.Client {
	return &http.Client{Transport: &http.Transport{TLSClientConfig: c.TLSClientConfig()}}
}

func (c *TLSConfigurator) loadServerCertPool() *x509.CertPool {
	if len(c.caCerts) == 0 {
		return nil
	}

	certPool := x509.NewCertPool()

	for _, cert := range c.caCerts {
		certPool.AppendCertsFromPEM(cert)
	}

	return certPool
}

func loadBytes(fs http.FileSystem, cert string) ([]byte, error) {
	if fs == nil {
		fs = http.Dir(filepath.Dir(cert))
		cert = filepath.Base(cert)
	}

	file, err := fs.Open(cert)
	if err != nil {
		return nil, err
	}

	return ioutil.ReadAll(file)
}

func beforeGo114(ver string) bool {
	minversion, err := version.NewVersion("1.14")
	if err != nil {
		return true
	}

	curversion, err := version.NewVersion(strings.TrimPrefix(ver, "go"))
	if err != nil {
		return true
	}

	return curversion.LessThan(minversion)
}
