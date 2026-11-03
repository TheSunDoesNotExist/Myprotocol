package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func material(t *testing.T) (config, config) {
	t.Helper()
	dir := t.TempDir()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "private.localhost"},
		DNSNames: []string{"private.localhost", "public.localhost"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, BasicConstraintsValid: true}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	pk, _ := x509.MarshalPKCS8PrivateKey(key)
	certPath, keyPath := filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem")
	os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0600)
	os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pk}), 0600)
	list, ech, err := makeECH("public.localhost")
	if err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal([]echKey{ech})
	keysPath, configPath := filepath.Join(dir, "keys.json"), filepath.Join(dir, "config.bin")
	os.WriteFile(keysPath, b, 0600)
	os.WriteFile(configPath, list, 0644)
	return config{Mode: "server", Cert: certPath, CertKey: keyPath, KeysFile: keysPath},
		config{Mode: "client", CA: certPath, ServerName: "private.localhost", ConfigFile: configPath}
}

func echoBackend(t *testing.T) (string, *atomic.Int32) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { listener.Close() })
	count := &atomic.Int32{}
	go func() {
		for {
			c, e := listener.Accept()
			if e != nil {
				return
			}
			count.Add(1)
			go func() { defer c.Close(); io.Copy(c, c) }()
		}
	}()
	return listener.Addr().String(), count
}

func TestECHTCPAndHTTP3(t *testing.T) {
	serverConfig, clientConfig := material(t)
	backend, _ := echoBackend(t)
	serverConfig.TCP, serverConfig.UDP = "127.0.0.1:0", "127.0.0.1:0"
	serverConfig.BackendTCP, serverConfig.BackendUDP = backend, backend
	server, err := start(serverConfig, string(bytes.Repeat([]byte{'a'}, 64)))
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	clientConfig.RemoteTCP, clientConfig.RemoteUDP = server.ready["tcp"], server.ready["udp"]
	client, err := start(clientConfig, server.key)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	for _, path := range []string{"tcp", "udp"} {
		t.Run(path, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			conn, err := client.dial(ctx, path)
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			data := bytes.Repeat([]byte("protected bytes"), 10000)
			sent := make(chan error, 1)
			go func() { _, e := conn.Write(data); sent <- e }()
			got := make([]byte, len(data))
			if _, err = io.ReadFull(conn, got); err != nil {
				t.Fatal(err)
			}
			if err = <-sent; err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(data, got) {
				t.Fatal("corrupt tunnel")
			}
		})
	}
}

type tapConn struct {
	net.Conn
	mu   *sync.Mutex
	wire *bytes.Buffer
}

func (c *tapConn) Read(b []byte) (int, error) {
	n, e := c.Conn.Read(b)
	c.mu.Lock()
	c.wire.Write(b[:n])
	c.mu.Unlock()
	return n, e
}

func TestClientHelloHidesPrivateNameAndPayload(t *testing.T) {
	sc, cc := material(t)
	backend, _ := echoBackend(t)
	sc.TCP = "127.0.0.1:0"
	sc.BackendTCP = backend
	server, err := start(sc, string(bytes.Repeat([]byte{'a'}, 64)))
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	proxy, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer proxy.Close()
	var mu sync.Mutex
	var wire bytes.Buffer
	done := make(chan struct{})
	go func() {
		defer close(done)
		c, e := proxy.Accept()
		if e != nil {
			return
		}
		up, e := net.Dial("tcp", server.ready["tcp"])
		if e != nil {
			c.Close()
			return
		}
		bridge(&tapConn{Conn: c, mu: &mu, wire: &wire}, up)
	}()
	cc.RemoteTCP = proxy.Addr().String()
	client, err := start(cc, server.key)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := client.dial(ctx, "tcp")
	if err != nil {
		t.Fatal(err)
	}
	payload := []byte("APPLICATION-SECRET-MUST-NOT-BE-VISIBLE")
	conn.Write(payload)
	got := make([]byte, len(payload))
	if _, err = io.ReadFull(conn, got); err != nil {
		t.Fatal(err)
	}
	conn.Close()
	<-done
	mu.Lock()
	defer mu.Unlock()
	for _, secret := range [][]byte{[]byte("private.localhost"), []byte("myownvpn"), []byte(server.key), payload} {
		if bytes.Contains(wire.Bytes(), secret) {
			t.Fatal("private data in outer wire")
		}
	}
	if !bytes.Contains(wire.Bytes(), []byte("public.localhost")) {
		t.Fatal("missing expected public SNI")
	}
}

func TestECHRejectionNeverSendsHTTPOrPayload(t *testing.T) {
	sc, cc := material(t)
	cert, err := tls.LoadX509KeyPair(sc.Cert, sc.CertKey)
	if err != nil {
		t.Fatal(err)
	}
	listener, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{MinVersion: tls.VersionTLS13, NextProtos: []string{"http/1.1"}, Certificates: []tls.Certificate{cert}})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	appBytes := make(chan int, 1)
	go func() {
		c, e := listener.Accept()
		if e != nil {
			appBytes <- -1
			return
		}
		defer c.Close()
		c.SetDeadline(time.Now().Add(4 * time.Second))
		b := make([]byte, 1)
		n, _ := c.Read(b)
		appBytes <- n
	}()
	cc.RemoteTCP = listener.Addr().String()
	client, err := start(cc, string(bytes.Repeat([]byte{'a'}, 64)))
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := client.dial(ctx, "tcp")
	var rejected *tls.ECHRejectionError
	if conn != nil || !errors.As(err, &rejected) {
		t.Fatalf("expected ECH rejection, got %T", err)
	}
	if n := <-appBytes; n != 0 {
		t.Fatalf("application bytes before ECH acceptance: %d", n)
	}
}

func TestECHPublicAndPrivateNamesMustDiffer(t *testing.T) {
	_, c := material(t)
	c.ServerName = "PUBLIC.LOCALHOST."
	if _, err := tlsConfig(c); err == nil {
		t.Fatal("ECH cannot hide a name also used as public SNI")
	}
}

func TestWrongConfigCertificateAndKeyNeverReachBackend(t *testing.T) {
	for _, failure := range []string{"ech_config", "hostname", "key"} {
		t.Run(failure, func(t *testing.T) {
			sc, cc := material(t)
			backend, count := echoBackend(t)
			sc.TCP, sc.UDP = "127.0.0.1:0", "127.0.0.1:0"
			sc.BackendTCP, sc.BackendUDP = backend, backend
			server, err := start(sc, string(bytes.Repeat([]byte{'a'}, 64)))
			if err != nil {
				t.Fatal(err)
			}
			defer server.Close()
			cc.RemoteTCP, cc.RemoteUDP = server.ready["tcp"], server.ready["udp"]
			key := server.key
			if failure == "hostname" {
				cc.ServerName = "wrong.localhost"
			}
			if failure == "key" {
				key = string(bytes.Repeat([]byte{'b'}, 64))
			}
			if failure == "ech_config" {
				list, _, _ := makeECH("public.localhost")
				os.WriteFile(cc.ConfigFile, list, 0644)
			}
			client, err := start(cc, key)
			if err != nil {
				t.Fatal(err)
			}
			defer client.Close()
			for _, path := range []string{"tcp", "udp"} {
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				conn, err := client.dial(ctx, path)
				cancel()
				if conn != nil {
					conn.Close()
					t.Fatal("unverified path accepted")
				}
				if err == nil {
					t.Fatal("missing rejection")
				}
			}
			if count.Load() != 0 {
				t.Fatal("rejected client reached inner backend")
			}
		})
	}
}
