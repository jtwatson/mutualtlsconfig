package mutualtlsconfig

import (
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"

	c "github.com/smartystreets/goconvey/convey"
)

func TestConfigurator(t *testing.T) {
	c.Convey("Given a TLSConfigurator", t, func() {
		c.Convey("which is configured for a Client with two CaCerts", func() {
			// Setup client
			config := &TLSConfigurator{
				Assets:  http.Dir("testdata"),
				CaCerts: []string{"serverca.crt", "clientca.crt"},
				Cert:    "client.crt",
				Key:     "client.key",
			}

			tlsConfig, err := config.TLSClientConfig()

			c.Convey("config.TLSClientConfig() should not error", func() {
				c.So(err, c.ShouldBeNil)
			})

			c.Convey("tlsConfig.RootCAs should not be nil", func() {
				c.So(tlsConfig.RootCAs, c.ShouldNotBeNil)
			})

			c.Convey("tlsConfig.Certificates should not be nil", func() {
				c.So(tlsConfig.Certificates, c.ShouldNotBeNil)
			})

			c.Convey("tlsConfig.RootCAs count should be 2", func() {
				c.So(len(tlsConfig.RootCAs.Subjects()), c.ShouldEqual, 2)
			})
		})

		c.Convey("which is configured for a Server with single CaCert", func() {
			// Setup server
			config := &TLSConfigurator{
				Assets:  http.Dir("testdata"),
				CaCerts: []string{"clientca.crt"},
				Cert:    "server.crt",
				Key:     "server.key",
			}

			tlsConfig, err := config.TLSServerConfig()

			c.Convey("config.TLSServerConfig() should not error", func() {
				c.So(err, c.ShouldBeNil)
			})

			c.Convey("tlsConfig.ClientAuth should be set to tls.RequireAndVerifyClientCert", func() {
				c.So(tlsConfig.ClientAuth, c.ShouldEqual, tls.RequireAndVerifyClientCert)
			})

			c.Convey("tlsConfig.Certificates should not be nil", func() {
				c.So(tlsConfig.Certificates, c.ShouldNotBeNil)
			})

			c.Convey("tlsConfig.ClientCAs count should be 1", func() {
				c.So(len(tlsConfig.ClientCAs.Subjects()), c.ShouldEqual, 1)
			})
		})

		c.Convey("which is configured for a Server with a missing cert", func() {
			// Setup server
			config := &TLSConfigurator{
				Assets:  http.Dir("testdata"),
				CaCerts: []string{"clientca.crt"},
				Cert:    "missing",
				Key:     "server.key",
			}

			tlsConfig, err := config.TLSServerConfig()

			c.Convey("config.TLSServerConfig() should error", c.FailureHalts, func() {
				c.So(err, c.ShouldNotBeNil)

				c.Convey("err should contain 'no such file or directory'", func() {
					c.So(err.Error(), c.ShouldContainSubstring, "no such file or directory")
				})
			})

			c.Convey("tlsConfig should be nil", func() {
				c.So(tlsConfig, c.ShouldBeNil)
			})
		})

		c.Convey("which is configured for a Server with a missing key", func() {
			// Setup server
			config := &TLSConfigurator{
				Assets:  http.Dir("testdata"),
				CaCerts: []string{"clientca.crt"},
				Cert:    "server.crt",
				Key:     "missing",
			}

			tlsConfig, err := config.TLSServerConfig()

			c.Convey("config.TLSServerConfig() should error", c.FailureHalts, func() {
				c.So(err, c.ShouldNotBeNil)

				c.Convey("err should contain 'no such file or directory'", func() {
					c.So(err.Error(), c.ShouldContainSubstring, "no such file or directory")
				})
			})

			c.Convey("tlsConfig should be nil", func() {
				c.So(tlsConfig, c.ShouldBeNil)
			})
		})

		c.Convey("which is configured for a Server with a missing caCert", func() {
			// Setup server
			config := &TLSConfigurator{
				Assets:  http.Dir("testdata"),
				CaCerts: []string{"missing"},
				Cert:    "server.crt",
				Key:     "server.key",
			}

			tlsConfig, err := config.TLSServerConfig()

			c.Convey("config.TLSServerConfig() should error", c.FailureHalts, func() {
				c.So(err, c.ShouldNotBeNil)

				c.Convey("err should contain 'no such file or directory'", func() {
					c.So(err.Error(), c.ShouldContainSubstring, "no such file or directory")
				})
			})

			c.Convey("tlsConfig should be nil", func() {
				c.So(tlsConfig, c.ShouldBeNil)
			})
		})

		c.Convey("which is configured for a Client with a missing key", func() {
			// Setup client
			config := &TLSConfigurator{
				Assets:  http.Dir("testdata"),
				CaCerts: []string{"serverca.crt"},
				Cert:    "client.crt",
				Key:     "missing",
			}

			tlsConfig, err := config.TLSClientConfig()

			c.Convey("config.TLSClientConfig() should error", c.FailureHalts, func() {
				c.So(err, c.ShouldNotBeNil)

				c.Convey("err should contain 'no such file or directory'", func() {
					c.So(err.Error(), c.ShouldContainSubstring, "no such file or directory")
				})
			})

			c.Convey("tlsConfig should be nil", func() {
				c.So(tlsConfig, c.ShouldBeNil)
			})
		})

		c.Convey("which is configured for a Client with a missing caCert", func() {
			// Setup client
			config := &TLSConfigurator{
				Assets:  http.Dir("testdata"),
				CaCerts: []string{"missing"},
				Cert:    "client.crt",
				Key:     "client.key",
			}

			tlsConfig, err := config.TLSClientConfig()

			c.Convey("config.TLSClientConfig() should error", c.FailureHalts, func() {
				c.So(err, c.ShouldNotBeNil)

				c.Convey("err should contain 'no such file or directory'", func() {
					c.So(err.Error(), c.ShouldContainSubstring, "no such file or directory")
				})
			})

			c.Convey("tlsConfig should be nil", func() {
				c.So(tlsConfig, c.ShouldBeNil)
			})
		})
	})

	c.Convey("Given a TLSConfigurator for both a Server and Client", t, func() {
		// Setup Client
		clientConfig := &TLSConfigurator{
			Assets:  http.Dir("testdata"),
			CaCerts: []string{"serverca.crt"},
			Cert:    "client.crt",
			Key:     "client.key",
		}

		// Setup Server
		serverConfig := &TLSConfigurator{
			Assets:  http.Dir("testdata"),
			CaCerts: []string{"clientca.crt"},
			Cert:    "server.crt",
			Key:     "server.key",
		}

		c.Convey("We can setup an secure tcp server and client", c.FailureHalts, func() {
			// Setup Server
			ln, err := net.Listen("tcp", "localhost:0")
			c.So(err, c.ShouldBeNil)

			tlsLn, err := serverConfig.TLSListener(ln)
			c.So(err, c.ShouldBeNil)

			go func() {
				conn, _ := tlsLn.Accept()
				io.Copy(conn, conn)
			}()

			// Setup Client
			tlsClientConfig, err := clientConfig.TLSClientConfig()
			c.So(err, c.ShouldBeNil)

			c.Convey("The client can connect to the server", func() {
				client, err := tls.Dial("tcp", ln.Addr().String(), tlsClientConfig)
				c.So(err, c.ShouldBeNil)

				c.Convey("And comunicate", func() {
					go func() {
						client.Write([]byte("Hello"))
					}()

					msg := make([]byte, 5)
					n, err := client.Read(msg)
					c.So(err, c.ShouldBeNil)

					err = client.Close()
					c.So(err, c.ShouldBeNil)

					c.So(n, c.ShouldEqual, 5)
					c.So(string(msg), c.ShouldEqual, "Hello")
				})
			})
		})

		c.Convey("We can setup an secure http client/server", c.FailureHalts, func() {
			// Setup Server
			ln, err := net.Listen("tcp", "localhost:0")
			c.So(err, c.ShouldBeNil)

			tlsLn, err := serverConfig.TLSListener(ln)
			c.So(err, c.ShouldBeNil)

			http.HandleFunc("/", echoHandler)

			go func() {
				http.Serve(tlsLn, nil)
			}()

			c.Convey("The client can communicate with the server", func() {
				request, err := http.NewRequest("Post", "https://"+ln.Addr().String(), strings.NewReader("Hello"))
				c.So(err, c.ShouldBeNil)

				client, err := clientConfig.HTTPSClient()
				c.So(err, c.ShouldBeNil)

				r, err := client.Do(request)
				c.So(err, c.ShouldBeNil)

				msg := make([]byte, 5)
				n, err := r.Body.Read(msg)
				c.So(err, c.ShouldEqual, io.EOF)

				err = r.Body.Close()
				c.So(err, c.ShouldBeNil)

				c.So(n, c.ShouldEqual, 5)
				c.So(string(msg), c.ShouldEqual, "Hello")
			})
		})
	})
}

func echoHandler(w http.ResponseWriter, r *http.Request) {
	io.Copy(w, r.Body)
	r.Body.Close()
}

// We can test that the tcpKeepAliveListener returns a good connection, but there is
// no API available test what the keepalive and deepalivepreiod have been set to. So
// we do the best that we can.
func TestTCPKeepAliveListener(t *testing.T) {
	c.Convey("Given a TCPListener wrapped in a tcpKeepAliveListener", t, func() {
		ln, _ := net.Listen("tcp", "127.0.0.1:0")
		kaln := &tcpKeepAliveListener{ln.(*net.TCPListener)}

		go func() {
			c, _ := net.Dial("tcp", ln.Addr().String())
			c.Write([]byte("Hello"))
			c.Close()
		}()

		c.Convey("Accepted connections should not have error", c.FailureHalts, func() {
			conn, err := kaln.Accept()

			c.So(err, c.ShouldBeNil)

			c.Convey("should receive without error", func() {
				v := make([]byte, 5)
				n, err := conn.Read(v)

				c.So(err, c.ShouldBeNil)
				c.So(n, c.ShouldEqual, 5)
				c.So(string(v), c.ShouldEqual, "Hello")
			})
		})

		c.Reset(func() {
			ln.Close()
		})
	})
}
