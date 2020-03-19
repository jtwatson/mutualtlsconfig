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
			config, err := NewFromFS(http.Dir("testdata"), "client.crt", "client.key", "serverca.crt", "clientca.crt")

			c.Convey("NewFromFS() should not error", func() {
				c.So(err, c.ShouldBeNil)
			})

			tlsConfig := config.TLSClientConfig()

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
			config, err := NewFromFile("testdata/server.crt", "testdata/server.key", "testdata/clientca.crt")

			c.Convey("NewFromFile() should not error", func() {
				c.So(err, c.ShouldBeNil)
			})

			tlsConfig := config.TLSServerConfig()

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
			config, err := NewFromFS(http.Dir("testdata"), "missing", "server.key", "clientca.crt")

			c.Convey("NewFromFS() should error", func() {
				c.So(err, c.ShouldNotBeNil)

				c.Convey("err should contain 'no such file or directory'", func() {
					c.So(err.Error(), c.ShouldContainSubstring, "no such file or directory")
				})
			})

			c.Convey("config should be nil", func() {
				c.So(config, c.ShouldBeNil)
			})
		})

		c.Convey("which is configured for a Server with a missing key", func() {
			// Setup server
			config, err := NewFromFS(http.Dir("testdata"), "server.crt", "missing", "clientca.crt")

			c.Convey("NewFromFS() should error", func() {
				c.So(err, c.ShouldNotBeNil)

				c.Convey("err should contain 'no such file or directory'", func() {
					c.So(err.Error(), c.ShouldContainSubstring, "no such file or directory")
				})
			})

			c.Convey("config should be nil", func() {
				c.So(config, c.ShouldBeNil)
			})
		})

		c.Convey("which is configured for a Server with a missing caCert", func() {
			// Setup server
			config, err := NewFromFS(http.Dir("testdata"), "server.crt", "server.key", "missing")

			c.Convey("NewFromFS() should error", func() {
				c.So(err, c.ShouldNotBeNil)

				c.Convey("err should contain 'no such file or directory'", func() {
					c.So(err.Error(), c.ShouldContainSubstring, "no such file or directory")
				})
			})

			c.Convey("config should be nil", func() {
				c.So(config, c.ShouldBeNil)
			})
		})

		c.Convey("which is configured for a Client with a missing key", func() {
			// Setup client
			config, err := NewFromFS(http.Dir("testdata"), "client.crt", "missing", "serverca.crt")

			c.Convey("NewFromFS() should error", func() {
				c.So(err, c.ShouldNotBeNil)

				c.Convey("err should contain 'no such file or directory'", func() {
					c.So(err.Error(), c.ShouldContainSubstring, "no such file or directory")
				})
			})

			c.Convey("config should be nil", func() {
				c.So(config, c.ShouldBeNil)
			})
		})

		c.Convey("which is configured for a Client with a missing caCert", func() {
			// Setup client
			config, err := NewFromFS(http.Dir("testdata"), "client.crt", "client.key", "missing")

			c.Convey("NewFromFS() should error", func() {
				c.So(err, c.ShouldNotBeNil)

				c.Convey("err should contain 'no such file or directory'", func() {
					c.So(err.Error(), c.ShouldContainSubstring, "no such file or directory")
				})
			})

			c.Convey("config should be nil", func() {
				c.So(config, c.ShouldBeNil)
			})
		})
	})

	c.Convey("Given a TLSConfigurator for both a Server and Client", t, func() {
		// Setup Client
		clientConfig, err := NewFromFS(http.Dir("testdata"), "client.crt", "client.key", "serverca.crt")

		c.Convey("client NewFromFS() should not error", c.FailureHalts, func() {
			c.So(err, c.ShouldBeNil)
		})

		// Setup Server
		serverConfig, err := NewFromFS(http.Dir("testdata"), "server.crt", "server.key", "clientca.crt")

		c.Convey("server NewFromFS() should not error", c.FailureHalts, func() {
			c.So(err, c.ShouldBeNil)
		})

		c.Convey("We can setup an secure tcp server and client", c.FailureHalts, func() {
			// Setup Server
			ln, err := net.Listen("tcp", "localhost:0")
			c.So(err, c.ShouldBeNil)

			tlsLn := serverConfig.TLSListener(ln)

			go func() {
				conn, _ := tlsLn.Accept()
				io.Copy(conn, conn)
			}()

			// Setup Client
			tlsClientConfig := clientConfig.TLSClientConfig()

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

			tlsLn := serverConfig.TLSListener(ln)

			http.HandleFunc("/", echoHandler)

			go func() {
				http.Serve(tlsLn, nil)
			}()

			c.Convey("The client can communicate with the server", func() {
				request, err := http.NewRequest("Post", "https://"+ln.Addr().String(), strings.NewReader("Hello"))
				c.So(err, c.ShouldBeNil)

				client := clientConfig.HTTPSClient()

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
