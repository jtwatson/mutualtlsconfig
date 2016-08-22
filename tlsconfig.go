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
	"time"
)

// TLSConfigurator is a utility to simplify setting up a Client/Server
// using TLS Mutual athentication. The tls.Config's returned will
// validate certificates for both the Client and Server.
type TLSConfigurator struct {
	Assets  http.FileSystem
	CaCerts []string
	Cert    string
	Key     string
}

// TLSClientConfig returns a tls.Config which will fully validate the
// server certificate using the provided CaCerts.
func (c *TLSConfigurator) TLSClientConfig() (*tls.Config, error) {

	caCertPool, err := c.loadServerCertPool()
	if err != nil {
		return nil, err
	}

	clientCert, err := c.loadCert()
	if err != nil {
		return nil, err
	}

	// Setup client
	tlsConfig := &tls.Config{
		RootCAs:      caCertPool,
		Certificates: []tls.Certificate{clientCert},
	}
	tlsConfig.BuildNameToCertificate()

	return tlsConfig, nil
}

// TLSServerConfig returns a tls.Config which will require and fully
// validate a client certificate using the provided CaCerts with
// option tls.RequireAndVerifyClientCert. The client
// certificate must have x509.ExtKeyUsageClientAuth set.
func (c *TLSConfigurator) TLSServerConfig() (*tls.Config, error) {

	caCertPool, err := c.loadServerCertPool()
	if err != nil {
		return nil, err
	}

	clientCert, err := c.loadCert()
	if err != nil {
		return nil, err
	}

	// Setup server
	tlsConfig := &tls.Config{
		ClientCAs:    caCertPool,
		Certificates: []tls.Certificate{clientCert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		NextProtos:   []string{"http/1.1"},
	}
	tlsConfig.BuildNameToCertificate()

	return tlsConfig, nil
}

// TLSListener wraps the TLSServerConfig around the net.Listener
func (c *TLSConfigurator) TLSListener(ln net.Listener) (net.Listener, error) {
	tlsConfig, err := c.TLSServerConfig()
	if err != nil {
		return nil, err
	}

	// Wrap in a listener that sets the keep-alive
	kaln := tcpKeepAliveListener{ln.(*net.TCPListener)}

	// Wrap in a TLS listener
	tlsListener := tls.NewListener(kaln, tlsConfig)

	return tlsListener, nil
}

// HTTPSClient returns a http.Client with its Transport configured for TLS.
func (c *TLSConfigurator) HTTPSClient() (*http.Client, error) {
	tlsConfig, err := c.TLSClientConfig()
	if err != nil {
		return nil, err
	}
	transport := &http.Transport{TLSClientConfig: tlsConfig}
	return &http.Client{Transport: transport}, nil
}

func (c *TLSConfigurator) loadCert() (tls.Certificate, error) {
	clientCertPEM, err := c.loadBytes(c.Cert)
	if err != nil {
		return tls.Certificate{}, err
	}

	clientKeyPEM, err := c.loadBytes(c.Key)
	if err != nil {
		return tls.Certificate{}, err
	}

	return tls.X509KeyPair(clientCertPEM, clientKeyPEM)
}

func (c *TLSConfigurator) loadServerCertPool() (*x509.CertPool, error) {
	if len(c.CaCerts) == 0 {
		return nil, nil
	}
	certPool := x509.NewCertPool()

	for _, cert := range c.CaCerts {
		certPEM, err := c.loadBytes(cert)
		if err != nil {
			return nil, err
		}
		certPool.AppendCertsFromPEM(certPEM)
	}
	return certPool, nil
}

func (c *TLSConfigurator) loadBytes(cert string) ([]byte, error) {
	file, err := c.Assets.Open(cert)
	if err != nil {
		return nil, err
	}
	return ioutil.ReadAll(file)
}

// tcpKeepAliveListener sets TCP keep-alive timeouts on accepted
// connections. It's used by TLSListener so dead TCP connections
// (e.g. closing laptop mid-download) eventually go away.
type tcpKeepAliveListener struct {
	*net.TCPListener
}

func (ln tcpKeepAliveListener) Accept() (c net.Conn, err error) {
	tc, err := ln.AcceptTCP()
	if err != nil {
		return
	}
	tc.SetKeepAlive(true)
	tc.SetKeepAlivePeriod(3 * time.Minute)
	return tc, nil
}
