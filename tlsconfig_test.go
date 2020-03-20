package mutualtlsconfig

import (
	"crypto/tls"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestConfigurator(t *testing.T) {
	tmpDir, err := ioutil.TempDir("", "mutualtlsconfig")
	if err != nil {
		t.Fatalf("Should have created a temp directory, but received error: %s", err)
	}

	defer os.RemoveAll(tmpDir)

	clientCertInfo := &CertificateInformation{
		Type:         ClientCertType,
		Days:         365,
		Organization: "Organization",
		CommonName:   "CommonName",
	}

	serverCertInfo := &CertificateInformation{
		Type:         ServerCertType,
		Begin:        time.Now(),
		Days:         365,
		Organization: "Organization",
		CommonName:   "CommonName",
		DNSNames:     []string{"localhost"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}

	ccert, ckey, err := clientCertInfo.Generate()
	if err != nil {
		t.Fatalf("clientCertInfo.Generate() should not error, but received: %s", err)
	}

	if err := ioutil.WriteFile(filepath.Join(tmpDir, "client.crt"), ccert, 0700); err != nil {
		t.Fatalf("ioutil.WriteFile() should not error for client.crt, but received: %s", err)
	}

	if err := ioutil.WriteFile(filepath.Join(tmpDir, "clientca.crt"), ccert, 0700); err != nil {
		t.Fatalf("ioutil.WriteFile() should not error for clientca.crt, but received: %s", err)
	}

	if err := ioutil.WriteFile(filepath.Join(tmpDir, "client.key"), ckey, 0700); err != nil {
		t.Fatalf("ioutil.WriteFile() should not error for client.key, but received: %s", err)
	}

	scert, skey, err := serverCertInfo.Generate()
	if err != nil {
		t.Fatalf("serverCertInfo.Generate() should not error, but received: %s", err)
	}

	if err := ioutil.WriteFile(filepath.Join(tmpDir, "server.crt"), scert, 0700); err != nil {
		t.Fatalf("ioutil.WriteFile() should not error for server.crt, but received: %s", err)
	}

	if err := ioutil.WriteFile(filepath.Join(tmpDir, "serverca.crt"), scert, 0700); err != nil {
		t.Fatalf("ioutil.WriteFile() should not error for serverca.crt, but received: %s", err)
	}

	if err := ioutil.WriteFile(filepath.Join(tmpDir, "server.key"), skey, 0700); err != nil {
		t.Fatalf("ioutil.WriteFile() should not error for server.key, but received: %s", err)
	}

	t.Run("Given a TLSConfigurator", func(t *testing.T) {
		t.Run("which is configured for a Client with two CaCerts", func(t *testing.T) {
			// Setup client
			config, err := NewFromFS(http.Dir(tmpDir), "client.crt", "client.key", "serverca.crt", "clientca.crt")
			if err != nil {
				t.Fatalf("NewFromFS() wantErr = nil, got %v", err)
			}

			tlsConfig := config.TLSClientConfig()
			if tlsConfig.Certificates == nil {
				t.Error("tlsConfig.Certificates should not be nil")
			}

			if tlsConfig.RootCAs == nil {
				t.Fatal("tlsConfig.RootCAs should not be nil")
			}

			if cnt := len(tlsConfig.RootCAs.Subjects()); cnt != 2 {
				t.Errorf("expected 2 RootCAs, got %d", cnt)
			}
		})

		t.Run("which is configured for a Server with single CaCert", func(t *testing.T) {
			// Setup server
			config, err := NewFromFile(filepath.Join(tmpDir, "server.crt"), filepath.Join(tmpDir, "server.key"), filepath.Join(tmpDir, "clientca.crt"))
			if err != nil {
				t.Fatalf("NewFromFile() wantErr = nil, got %v", err)
			}

			tlsConfig := config.TLSServerConfig()
			if tlsConfig.Certificates == nil {
				t.Error("tlsConfig.Certificates should not be nil")
			}

			if tlsConfig.ClientAuth != tls.RequireAndVerifyClientCert {
				t.Errorf("expected tlsConfig.ClientAuth = %v, got %v", tlsConfig.ClientAuth, tls.RequireAndVerifyClientCert)
			}

			if tlsConfig.ClientCAs == nil {
				t.Fatal("tlsConfig.ClientCAs should not be nil")
			}

			if cnt := len(tlsConfig.ClientCAs.Subjects()); cnt != 1 {
				t.Errorf("expected 1 ClientCAs, got %d", cnt)
			}
		})

		t.Run("which is configured for a Server with no CaCert", func(t *testing.T) {
			// Setup server
			config, err := NewFromFile(filepath.Join(tmpDir, "server.crt"), filepath.Join(tmpDir, "server.key"))
			if err != nil {
				t.Fatalf("NewFromFile() wantErr = nil, got %v", err)
			}

			tlsConfig := config.TLSServerConfig()
			if tlsConfig.Certificates == nil {
				t.Error("tlsConfig.Certificates should not be nil")
			}

			if tlsConfig.ClientAuth != tls.RequireAndVerifyClientCert {
				t.Errorf("expected tlsConfig.ClientAuth = %v, got %v", tlsConfig.ClientAuth, tls.RequireAndVerifyClientCert)
			}

			if tlsConfig.ClientCAs != nil {
				t.Errorf("tlsConfig.ClientCAs should be nil")
			}
		})

		t.Run("which is configured for a Server with a missing cert", func(t *testing.T) {
			// Setup server
			config, err := NewFromFS(http.Dir(tmpDir), "missing", "server.key", "clientca.crt")

			t.Run("NewFromFS() should error", func(t *testing.T) {
				if err == nil {
					t.Fatal("NewFromFS() wantErr != nil, got nil")
				}

				if !strings.Contains(err.Error(), "no such file or directory") {
					t.Errorf("err.Error() should contain %q, got %v", "no such file or directory", err)
				}
			})

			t.Run("config should be nil", func(t *testing.T) {
				if config != nil {
					t.Error("config != nil, expected nil")
				}
			})
		})

		t.Run("which is configured for a Server with a missing key", func(t *testing.T) {
			// Setup server
			config, err := NewFromFS(http.Dir(tmpDir), "server.crt", "missing", "clientca.crt")

			t.Run("NewFromFS() should error", func(t *testing.T) {
				if err == nil {
					t.Fatal("NewFromFS() wantErr != nil, got nil")
				}

				if !strings.Contains(err.Error(), "no such file or directory") {
					t.Errorf("err.Error() should contain %q, got %v", "no such file or directory", err)
				}
			})

			t.Run("config should be nil", func(t *testing.T) {
				if config != nil {
					t.Error("config != nil, expected nil")
				}
			})
		})

		t.Run("which is configured for a Server with a missing caCert", func(t *testing.T) {
			// Setup server
			config, err := NewFromFS(http.Dir(tmpDir), "server.crt", "server.key", "missing")

			t.Run("NewFromFS() should error", func(t *testing.T) {
				if err == nil {
					t.Fatal("NewFromFS() wantErr != nil, got nil")
				}

				if !strings.Contains(err.Error(), "no such file or directory") {
					t.Errorf("err.Error() should contain %q, got %v", "no such file or directory", err)
				}
			})

			t.Run("config should be nil", func(t *testing.T) {
				if config != nil {
					t.Error("config != nil, expected nil")
				}
			})
		})

		t.Run("which is configured for a Client with a missing key", func(t *testing.T) {
			// Setup client
			config, err := NewFromFS(http.Dir(tmpDir), "client.crt", "missing", "serverca.crt")

			t.Run("NewFromFS() should error", func(t *testing.T) {
				if err == nil {
					t.Fatal("NewFromFS() wantErr != nil, got nil")
				}

				if !strings.Contains(err.Error(), "no such file or directory") {
					t.Errorf("err.Error() should contain %q, got %v", "no such file or directory", err)
				}
			})

			t.Run("config should be nil", func(t *testing.T) {
				if config != nil {
					t.Error("config != nil, expected nil")
				}
			})
		})

		t.Run("which is configured for a Client with a missing caCert", func(t *testing.T) {
			// Setup client
			config, err := NewFromFS(http.Dir(tmpDir), "client.crt", "client.key", "missing")

			t.Run("NewFromFS() should error", func(t *testing.T) {
				if err == nil {
					t.Fatal("NewFromFS() wantErr != nil, got nil")
				}

				if !strings.Contains(err.Error(), "no such file or directory") {
					t.Errorf("err.Error() should contain %q, got %v", "no such file or directory", err)
				}
			})

			t.Run("config should be nil", func(t *testing.T) {
				if config != nil {
					t.Error("config != nil, expected nil")
				}
			})
		})
	})

	t.Run("Given a TLSConfigurator for both a Server and Client", func(t *testing.T) {
		// Setup Client
		clientConfig, err := NewFromFS(http.Dir(tmpDir), "client.crt", "client.key", "serverca.crt")
		if err != nil {
			t.Fatalf("client NewFromFS() wantErr = nil, got %v", err)
		}

		// Setup Server
		serverConfig, err := NewFromFS(http.Dir(tmpDir), "server.crt", "server.key", "clientca.crt")
		if err != nil {
			t.Fatalf("server NewFromFS() wantErr = nil, got %v", err)
		}

		t.Run("We can setup an secure tcp server and client", func(t *testing.T) {
			// Setup Server
			ln, err := net.Listen("tcp", "localhost:0")
			if err != nil {
				t.Fatalf("net.Listen() wantErr = nil, got %v", err)
			}

			tlsLn := serverConfig.TLSListener(ln)

			go func() {
				conn, _ := tlsLn.Accept()
				io.Copy(conn, conn)
			}()

			// Setup Client
			tlsClientConfig := clientConfig.TLSClientConfig()

			t.Run("The client can connect to the server", func(t *testing.T) {
				client, err := tls.Dial("tcp", ln.Addr().String(), tlsClientConfig)
				if err != nil {
					t.Fatalf("tls.Dial() wantErr = nil, got %v", err)
				}

				t.Run("And comunicate", func(t *testing.T) {
					go func() {
						client.Write([]byte("Hello"))
					}()

					msg := make([]byte, 5)
					n, err := client.Read(msg)
					if err != nil {
						t.Fatalf("client.Read() wantErr = nil, got %v", err)
					}

					err = client.Close()
					if err != nil {
						t.Errorf("client.Close() wantErr = nil, got %v", err)
					}

					if n != 5 {
						t.Errorf("expected to read 5 bytes, got %d", n)
					}

					if string(msg) != "Hello" {
						t.Errorf("expected %q, got %q", "Hello", msg)
					}
				})
			})
		})

		t.Run("We can setup an secure http client/server", func(t *testing.T) {
			// Setup Server
			ln, err := net.Listen("tcp", "localhost:0")
			if err != nil {
				t.Fatalf("net.Listen() wantErr = nil, got %v", err)
			}

			tlsLn := serverConfig.TLSListener(ln)

			http.HandleFunc("/", echoHandler)

			go func() {
				http.Serve(tlsLn, nil)
			}()

			t.Run("The client can communicate with the server", func(t *testing.T) {
				request, err := http.NewRequest("Post", "https://"+ln.Addr().String(), strings.NewReader("Hello"))
				if err != nil {
					t.Fatalf("http.NewRequest() wantErr = nil, got %v", err)
				}

				client := clientConfig.HTTPSClient()

				r, err := client.Do(request)
				if err != nil {
					t.Fatalf("client.Do() wantErr = nil, got %v", err)
				}

				msg := make([]byte, 5)
				n, err := r.Body.Read(msg)
				if err != io.EOF {
					t.Errorf("Body.Close() wantErr = %v, got %v", io.EOF, err)
				}

				err = r.Body.Close()
				if err != nil {
					t.Errorf("Body.Close() wantErr = nil, got %v", err)
				}

				if n != 5 {
					t.Errorf("expected to read 5 bytes, got %d", n)
				}

				if string(msg) != "Hello" {
					t.Errorf("expected %q, got %q", "Hello", msg)
				}
			})
		})
	})
}

func echoHandler(w http.ResponseWriter, r *http.Request) {
	io.Copy(w, r.Body)
	r.Body.Close()
}

func Test_beforeGo114(t *testing.T) {
	type args struct {
		ver string
	}

	tests := []struct {
		name string
		args args
		want bool
	}{
		{name: "Go1.14.1", args: args{"go1.14.1"}, want: false},
		{name: "Go1.14", args: args{"go1.14"}, want: false},
		{name: "Go1.13", args: args{"go1.13"}, want: true},
		{name: "Go1.13.12", args: args{"go1.13.12"}, want: true},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			if got := beforeGo114(tt.args.ver); got != tt.want {
				t.Errorf("beforeGo114() = %v, want %v", got, tt.want)
			}
		})
	}
}
