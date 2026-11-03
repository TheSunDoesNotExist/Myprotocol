// ECH wraps the existing authenticated TLS channel; it never replaces its checks.
package main

import (
	"bufio"
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	quic "github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"golang.org/x/crypto/cryptobyte"
)

const authority = "relay.internal:443"
const headerLimit = 8192
const authTimeout = 5 * time.Second

var errPolicy = errors.New("security policy")

type config struct {
	Mode       string `json:"mode"`
	TCP        string `json:"tcp"`
	UDP        string `json:"udp"`
	BackendTCP string `json:"backend_tcp"`
	BackendUDP string `json:"backend_udp"`
	RemoteTCP  string `json:"remote_tcp"`
	RemoteUDP  string `json:"remote_udp"`
	Cert       string `json:"cert"`
	CertKey    string `json:"cert_key"`
	CA         string `json:"ca"`
	ServerName string `json:"server_name"`
	ConfigFile string `json:"config_file"`
	KeysFile   string `json:"keys_file"`
	PublicName string `json:"public_name"`
}

type echKey struct {
	Config     []byte `json:"config"`
	PrivateKey []byte `json:"private_key"`
}

func logEvent(name, path, reason string) {
	// No raw errors, URLs, headers, names, keys or TLS secrets.
	b, _ := json.Marshal(map[string]any{"event": name, "path": path, "reason": reason})
	fmt.Fprintln(os.Stderr, string(b))
}

func readSmall(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, 65537))
	if len(b) > 65536 {
		return nil, errPolicy
	}
	return b, err
}

func writeNew(path string, b []byte, mode os.FileMode) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = f.Write(b)
	return err
}

func vec(b []byte) []byte { return append(binary.BigEndian.AppendUint16(nil, uint16(len(b))), b...) }

func makeECH(publicName string) ([]byte, echKey, error) {
	if len(publicName) == 0 || len(publicName) > 253 || net.ParseIP(publicName) != nil ||
		strings.ContainsAny(publicName, " /\\\r\n\t:") {
		return nil, echKey{}, errPolicy
	}
	private, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, echKey{}, err
	}
	id := make([]byte, 1)
	if _, err = rand.Read(id); err != nil {
		return nil, echKey{}, err
	}
	// RFC 9849 ECHConfig encoding only. HPKE and TLS are implemented by crypto/tls.
	body := append(id, 0, 0x20) // DHKEM(X25519, HKDF-SHA256)
	body = append(body, vec(private.PublicKey().Bytes())...)
	body = append(body, 0, 4, 0, 1, 0, 1)         // HKDF-SHA256, AES-128-GCM
	body = append(body, 0, byte(len(publicName))) // maximum_name_length, public_name
	body = append(body, publicName...)
	body = append(body, 0, 0) // extensions
	encoded := append([]byte{0xfe, 0x0d}, vec(body)...)
	return vec(encoded), echKey{Config: encoded, PrivateKey: private.Bytes()}, nil
}

func tlsConfig(c config) (*tls.Config, error) {
	t := &tls.Config{MinVersion: tls.VersionTLS13, SessionTicketsDisabled: true}
	if c.Mode == "server" {
		cert, err := tls.LoadX509KeyPair(c.Cert, c.CertKey)
		if err != nil {
			return nil, err
		}
		b, err := readSmall(c.KeysFile)
		if err != nil {
			return nil, err
		}
		var keys []echKey
		if json.Unmarshal(b, &keys) != nil || len(keys) == 0 || len(keys) > 4 {
			return nil, errPolicy
		}
		for _, key := range keys {
			t.EncryptedClientHelloKeys = append(t.EncryptedClientHelloKeys,
				tls.EncryptedClientHelloKey{Config: key.Config, PrivateKey: key.PrivateKey, SendAsRetry: true})
		}
		t.Certificates = []tls.Certificate{cert}
	} else {
		b, err := readSmall(c.CA)
		if err != nil {
			return nil, err
		}
		roots := x509.NewCertPool()
		if !roots.AppendCertsFromPEM(b) {
			return nil, errPolicy
		}
		ech, err := readSmall(c.ConfigFile)
		if err != nil || len(ech) == 0 {
			return nil, errPolicy
		}
		if c.ServerName == "" || net.ParseIP(c.ServerName) != nil {
			return nil, errPolicy
		}
		if err := checkPublicNames(ech, c.ServerName); err != nil {
			return nil, err
		}
		t.RootCAs, t.ServerName, t.EncryptedClientHelloConfigList = roots, c.ServerName, ech
		// No rejection callback or retry without ECH. No application bytes before success.
	}
	return t, nil
}

func checkPublicNames(encoded []byte, inner string) error {
	all := cryptobyte.String(encoded)
	var list cryptobyte.String
	if !all.ReadUint16LengthPrefixed(&list) || !all.Empty() {
		return errPolicy
	}
	for !list.Empty() {
		var version uint16
		var body, key, suites, public, extensions cryptobyte.String
		if !list.ReadUint16(&version) || !list.ReadUint16LengthPrefixed(&body) {
			return errPolicy
		}
		if version != 0xfe0d {
			continue
		}
		if !body.Skip(3) || !body.ReadUint16LengthPrefixed(&key) || !body.ReadUint16LengthPrefixed(&suites) ||
			!body.Skip(1) || !body.ReadUint8LengthPrefixed(&public) || !body.ReadUint16LengthPrefixed(&extensions) || !body.Empty() {
			return errPolicy
		}
		if strings.EqualFold(strings.TrimRight(string(public), "."), strings.TrimRight(inner, ".")) {
			return errPolicy
		}
	}
	return nil
}

type budget struct {
	sync.Mutex
	active, pending int
	ips             map[string]int
}
type lease struct {
	b               *budget
	ip              string
	pending, closed bool
	deadline        time.Time
}
type leaseKey struct{}

func (b *budget) acquire(addr net.Addr) (*lease, error) {
	ip, _, err := net.SplitHostPort(addr.String())
	if err != nil {
		return nil, err
	}
	b.Lock()
	defer b.Unlock()
	if b.active >= 64 || b.pending >= 32 || b.ips[ip] >= 8 {
		return nil, errPolicy
	}
	if b.ips == nil {
		b.ips = make(map[string]int)
	}
	b.active++
	b.pending++
	b.ips[ip]++
	return &lease{b: b, ip: ip, pending: true, deadline: time.Now().Add(authTimeout)}, nil
}
func (l *lease) authorize() bool {
	l.b.Lock()
	defer l.b.Unlock()
	if l.closed || time.Now().After(l.deadline) {
		return false
	}
	if l.pending {
		l.pending = false
		l.b.pending--
		l.b.ips[l.ip]--
		if l.b.ips[l.ip] == 0 {
			delete(l.b.ips, l.ip)
		}
	}
	return true
}
func (l *lease) release() {
	l.b.Lock()
	defer l.b.Unlock()
	if l.closed {
		return
	}
	l.closed = true
	l.b.active--
	if l.pending {
		l.b.pending--
		l.b.ips[l.ip]--
		if l.b.ips[l.ip] == 0 {
			delete(l.b.ips, l.ip)
		}
	}
}
func (l *lease) awaiting() bool { l.b.Lock(); defer l.b.Unlock(); return l.pending && !l.closed }

func quicConfig() *quic.Config {
	return &quic.Config{HandshakeIdleTimeout: 3 * time.Second, MaxIdleTimeout: 8 * time.Second,
		InitialStreamReceiveWindow: 96 * 1024, MaxStreamReceiveWindow: 96 * 1024,
		InitialConnectionReceiveWindow: 256 * 1024, MaxConnectionReceiveWindow: 256 * 1024,
		MaxIncomingStreams: 1, MaxIncomingUniStreams: 3, Allow0RTT: false}
}

type gateway struct {
	c       config
	tls     *tls.Config
	key     string
	ctx     context.Context
	cancel  context.CancelFunc
	closers []io.Closer
	wg      sync.WaitGroup
	ready   map[string]string
}

func loopback(address string) bool {
	host, _, err := net.SplitHostPort(address)
	return err == nil && net.ParseIP(host) != nil && net.ParseIP(host).IsLoopback()
}

func start(c config, key string) (*gateway, error) {
	if len(key) != 64 {
		return nil, errPolicy
	}
	for _, v := range key {
		if !strings.ContainsRune("0123456789abcdefABCDEF", v) {
			return nil, errPolicy
		}
	}
	if c.Mode != "client" && c.Mode != "server" {
		return nil, errPolicy
	}
	if c.Mode == "client" && ((!loopback(c.TCP) && c.TCP != "") || (!loopback(c.UDP) && c.UDP != "")) {
		return nil, errPolicy
	}
	if c.Mode == "client" {
		// Pinned ECH must not leak the private name through plaintext DNS bootstrap.
		for _, remote := range []string{c.RemoteTCP, c.RemoteUDP} {
			if remote == "" {
				continue
			}
			host, _, err := net.SplitHostPort(remote)
			if err != nil || net.ParseIP(host) == nil {
				return nil, errPolicy
			}
		}
	}
	if c.Mode == "server" && ((!loopback(c.BackendTCP) && c.TCP != "") || (!loopback(c.BackendUDP) && c.UDP != "")) {
		return nil, errPolicy
	}
	t, err := tlsConfig(c)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithCancel(context.Background())
	g := &gateway{c: c, tls: t, key: key, ctx: ctx, cancel: cancel, ready: make(map[string]string)}
	for _, path := range []string{"tcp", "udp"} {
		addr := c.TCP
		if path == "udp" {
			addr = c.UDP
		}
		if addr == "" {
			continue
		}
		if c.Mode == "server" && path == "udp" {
			err = g.listenH3(addr)
		} else {
			err = g.listenTCP(path, addr)
		}
		if err != nil {
			g.Close()
			return nil, err
		}
	}
	return g, nil
}

func (g *gateway) Close() error {
	g.cancel()
	for _, c := range g.closers {
		c.Close()
	}
	g.wg.Wait()
	return nil
}

func (g *gateway) listenTCP(path, address string) error {
	listener, err := net.Listen("tcp", address)
	if err != nil {
		return err
	}
	g.closers = append(g.closers, listener)
	g.ready[path] = listener.Addr().String()
	b := &budget{}
	g.wg.Add(1)
	go func() {
		defer g.wg.Done()
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			l, err := b.acquire(conn.RemoteAddr())
			if err != nil {
				conn.Close()
				continue
			}
			g.wg.Add(1)
			go func() {
				defer g.wg.Done()
				defer l.release()
				defer conn.Close()
				stop := context.AfterFunc(g.ctx, func() { conn.Close() })
				defer stop()
				if g.c.Mode == "server" {
					g.serveTCP(conn, l)
				} else {
					ctx, cancel := context.WithDeadline(g.ctx, l.deadline)
					defer cancel()
					upstream, err := g.dial(ctx, path)
					if err != nil {
						logEvent("ech_connection_failed", path, failureReason(err))
						return
					}
					defer upstream.Close()
					if !l.authorize() {
						return
					}
					logEvent("ech_accepted", path, "verified")
					bridge(conn, upstream)
				}
			}()
		}
	}()
	return nil
}

func validRequest(r *http.Request, state *tls.ConnectionState, key string) bool {
	return state != nil && state.ECHAccepted && state.Version == tls.VersionTLS13 &&
		r.Method == "CONNECT" && r.Host == authority && r.ContentLength <= 0 &&
		len(r.TransferEncoding) == 0 && len(r.Header.Values("Proxy-Authorization")) == 1 &&
		subtle.ConstantTimeCompare([]byte(r.Header.Get("Proxy-Authorization")), []byte("Bearer "+key)) == 1
}

func (g *gateway) serveTCP(raw net.Conn, l *lease) {
	t := g.tls.Clone()
	t.NextProtos = []string{"http/1.1"}
	conn := tls.Server(raw, t)
	defer conn.Close()
	conn.SetDeadline(l.deadline)
	if err := conn.HandshakeContext(g.ctx); err != nil {
		return
	}
	limited := &io.LimitedReader{R: conn, N: headerLimit + 1}
	reader := bufio.NewReaderSize(limited, headerLimit+1)
	r, err := http.ReadRequest(reader)
	if err != nil || limited.N == 0 {
		return
	}
	state := conn.ConnectionState()
	if !validRequest(r, &state, g.key) || state.NegotiatedProtocol != "http/1.1" || !l.authorize() {
		status, body := "404 Not Found", "Not found.\n"
		if (r.Method == "GET" || r.Method == "HEAD") && r.RequestURI == "/" {
			status, body = "200 OK", "Service online.\n"
		}
		fmt.Fprintf(conn, "HTTP/1.1 %s\r\nContent-Length: %d\r\nConnection: close\r\n\r\n", status, len(body))
		if r.Method != "HEAD" {
			io.WriteString(conn, body)
		}
		return
	}
	backend, err := (&net.Dialer{Timeout: 3 * time.Second}).DialContext(g.ctx, "tcp", g.c.BackendTCP)
	if err != nil {
		return
	}
	defer backend.Close()
	conn.SetDeadline(time.Time{})
	io.WriteString(conn, "HTTP/1.1 200 Connection Established\r\n\r\n")
	logEvent("ech_accepted", "tcp", "verified")
	bridge(&bufferedConn{Conn: conn, reader: io.MultiReader(reader, conn)}, backend)
}

type bufferedConn struct {
	net.Conn
	reader io.Reader
}

func (c *bufferedConn) Read(b []byte) (int, error) { return c.reader.Read(b) }

func bridge(a, b io.ReadWriteCloser) {
	done := make(chan struct{}, 2)
	copyOne := func(dst io.Writer, src io.Reader) { io.CopyBuffer(dst, src, make([]byte, 32*1024)); done <- struct{}{} }
	go copyOne(a, b)
	go copyOne(b, a)
	<-done
	a.Close()
	b.Close()
	<-done
}

func (g *gateway) listenH3(address string) error {
	udpAddr, err := net.ResolveUDPAddr("udp", address)
	if err != nil {
		return err
	}
	socket, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		return err
	}
	b := &budget{}
	transport := &quic.Transport{Conn: socket, VerifySourceAddress: func(net.Addr) bool { return true },
		ConnContext: func(ctx context.Context, info *quic.ClientInfo) (context.Context, error) {
			l, err := b.acquire(info.RemoteAddr)
			if err != nil {
				return nil, err
			}
			context.AfterFunc(ctx, l.release)
			return context.WithValue(ctx, leaseKey{}, l), nil
		}}
	t := g.tls.Clone()
	t.NextProtos = []string{http3.NextProtoH3}
	listener, err := transport.ListenEarly(t, quicConfig())
	if err != nil {
		transport.Close()
		socket.Close()
		return err
	}
	server := &http3.Server{MaxHeaderBytes: headerLimit, IdleTimeout: 8 * time.Second, Handler: http.HandlerFunc(g.serveH3)}
	g.closers = append(g.closers, listener, server, transport, socket)
	g.ready["udp"] = socket.LocalAddr().String()
	g.wg.Add(1)
	go func() {
		defer g.wg.Done()
		for {
			conn, err := listener.Accept(g.ctx)
			if err != nil {
				return
			}
			g.wg.Add(1)
			go func() {
				defer g.wg.Done()
				defer conn.CloseWithError(0, "")
				l := conn.Context().Value(leaseKey{}).(*lease)
				timer := time.AfterFunc(time.Until(l.deadline), func() {
					if l.awaiting() {
						conn.CloseWithError(0, "")
					}
				})
				defer timer.Stop()
				server.ServeQUICConn(conn)
			}()
		}
	}()
	return nil
}

func (g *gateway) serveH3(w http.ResponseWriter, r *http.Request) {
	l := r.Context().Value(leaseKey{}).(*lease)
	if !validRequest(r, r.TLS, g.key) || !l.authorize() {
		if (r.Method == "GET" || r.Method == "HEAD") && r.URL.Path == "/" {
			io.WriteString(w, "Service online.\n")
		} else {
			http.NotFound(w, r)
		}
		return
	}
	backend, err := (&net.Dialer{Timeout: 3 * time.Second}).DialContext(r.Context(), "tcp", g.c.BackendUDP)
	if err != nil {
		w.WriteHeader(502)
		return
	}
	defer backend.Close()
	w.WriteHeader(200)
	stream := w.(http3.HTTPStreamer).HTTPStream()
	defer stream.CancelRead(0)
	logEvent("ech_accepted", "udp", "verified")
	bridge(stream, backend)
}

func (g *gateway) dial(ctx context.Context, path string) (io.ReadWriteCloser, error) {
	t := g.tls.Clone()
	if path == "udp" {
		return g.dialH3(ctx, t)
	}
	t.NextProtos = []string{"http/1.1"}
	raw, err := (&net.Dialer{Timeout: 3 * time.Second, FallbackDelay: 250 * time.Millisecond}).DialContext(ctx, "tcp", g.c.RemoteTCP)
	if err != nil {
		return nil, err
	}
	conn := tls.Client(raw, t)
	stop := context.AfterFunc(ctx, func() { conn.Close() })
	defer stop()
	if err = conn.HandshakeContext(ctx); err != nil {
		conn.Close()
		return nil, err
	}
	state := conn.ConnectionState()
	if !state.ECHAccepted || state.NegotiatedProtocol != "http/1.1" {
		conn.Close()
		return nil, errPolicy
	}
	conn.SetDeadline(time.Now().Add(3 * time.Second))
	if deadline, ok := ctx.Deadline(); ok && time.Until(deadline) < 3*time.Second {
		conn.SetDeadline(deadline)
	}
	fmt.Fprintf(conn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\nProxy-Authorization: Bearer %s\r\n\r\n", authority, authority, g.key)
	limited := &io.LimitedReader{R: conn, N: headerLimit + 1}
	reader := bufio.NewReaderSize(limited, headerLimit+1)
	response, err := http.ReadResponse(reader, &http.Request{Method: "CONNECT"})
	if err != nil || limited.N == 0 || response.StatusCode != 200 ||
		response.Header.Get("Content-Length") != "" || len(response.TransferEncoding) != 0 {
		conn.Close()
		return nil, errPolicy
	}
	conn.SetDeadline(time.Time{})
	return &bufferedConn{Conn: conn, reader: io.MultiReader(reader, conn)}, nil
}

type h3Tunnel struct {
	*http3.RequestStream
	conn *quic.Conn
}

func (s *h3Tunnel) Close() error {
	s.CancelRead(0)
	s.CancelWrite(0)
	return s.conn.CloseWithError(0, "")
}

func (g *gateway) dialH3Address(ctx context.Context, t *tls.Config, addr string) (io.ReadWriteCloser, error) {
	conn, err := quic.DialAddr(ctx, addr, t, quicConfig())
	if err != nil {
		return nil, err
	}
	stop := context.AfterFunc(ctx, func() { conn.CloseWithError(0, "") })
	defer stop()
	ok := false
	defer func() {
		if !ok {
			conn.CloseWithError(0, "")
		}
	}()
	if !conn.ConnectionState().TLS.ECHAccepted {
		return nil, errPolicy
	}
	tr := &http3.Transport{DisableCompression: true, MaxResponseHeaderBytes: headerLimit}
	client := tr.NewClientConn(conn)
	stream, err := client.OpenRequestStream(ctx)
	if err != nil {
		return nil, err
	}
	stream.SetDeadline(time.Now().Add(3 * time.Second))
	request := &http.Request{Method: "CONNECT", URL: &url.URL{Scheme: "https", Host: authority}, Host: authority,
		Header: http.Header{"Proxy-Authorization": []string{"Bearer " + g.key}}}
	if err = stream.SendRequestHeader(request); err != nil {
		return nil, err
	}
	response, err := stream.ReadResponse()
	if err != nil || response.StatusCode != 200 || response.Header.Get("Content-Length") != "" {
		return nil, errPolicy
	}
	stream.SetDeadline(time.Time{})
	ok = true
	return &h3Tunnel{RequestStream: stream, conn: conn}, nil
}

func (g *gateway) dialH3(ctx context.Context, t *tls.Config) (io.ReadWriteCloser, error) {
	t.NextProtos = []string{http3.NextProtoH3}
	host, port, err := net.SplitHostPort(g.c.RemoteUDP)
	if err != nil {
		return nil, err
	}
	ips, err := net.DefaultResolver.LookupIPAddr(ctx, host)
	if err != nil {
		return nil, err
	}
	// Alternate families with bounded attempts, preserving the original TLS name.
	var first, second []net.IPAddr
	for _, ip := range ips {
		if len(ips) > 0 && (ip.IP.To4() != nil) == (ips[0].IP.To4() != nil) {
			first = append(first, ip)
		} else {
			second = append(second, ip)
		}
	}
	var addresses []string
	for len(first) > 0 || len(second) > 0 {
		for _, group := range []*[]net.IPAddr{&first, &second} {
			if len(*group) > 0 && len(addresses) < 8 {
				ip := (*group)[0]
				*group = (*group)[1:]
				addresses = append(addresses, net.JoinHostPort(ip.String(), port))
			} else if len(*group) > 0 {
				*group = nil
			}
		}
	}
	if len(addresses) == 0 {
		return nil, errPolicy
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	type result struct {
		conn io.ReadWriteCloser
		err  error
	}
	results := make(chan result, len(addresses))
	for i, addr := range addresses {
		go func() {
			timer := time.NewTimer(time.Duration(i) * 250 * time.Millisecond)
			defer timer.Stop()
			select {
			case <-ctx.Done():
				results <- result{err: ctx.Err()}
				return
			case <-timer.C:
			}
			c, e := g.dialH3Address(ctx, t.Clone(), addr)
			results <- result{c, e}
		}()
	}
	var last error
	for remaining := len(addresses); remaining > 0; remaining-- {
		r := <-results
		if r.err == nil {
			cancel()
			g.wg.Add(1)
			go func(n int) {
				defer g.wg.Done()
				for range n {
					loser := <-results
					if loser.conn != nil {
						loser.conn.Close()
					}
				}
			}(remaining - 1)
			return r.conn, nil
		}
		if r.err != nil {
			last = r.err
		}
	}
	return nil, last
}

func failureReason(err error) string {
	var rejected *tls.ECHRejectionError
	var cert *tls.CertificateVerificationError
	if errors.As(err, &rejected) {
		return "ech_rejected"
	}
	if errors.As(err, &cert) {
		return "certificate_verification_failed"
	}
	if errors.Is(err, errPolicy) {
		return "authentication_or_protocol_failed"
	}
	return "network_error"
}

func run() error {
	var c config
	decoder := json.NewDecoder(io.LimitReader(os.Stdin, 65537))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&c); err != nil {
		return err
	}
	if c.Mode == "keygen" {
		list, key, err := makeECH(c.PublicName)
		if err != nil {
			return err
		}
		b, _ := json.MarshalIndent([]echKey{key}, "", "  ")
		if err = writeNew(c.KeysFile, b, 0600); err != nil {
			return err
		}
		return writeNew(c.ConfigFile, list, 0644)
	}
	g, err := start(c, os.Getenv("MYVPN_KEY"))
	if err != nil {
		return err
	}
	defer g.Close()
	if err = json.NewEncoder(os.Stdout).Encode(g.ready); err != nil {
		return err
	}
	// Parent EOF is the lifeline. All accepted sockets and QUIC goroutines stop.
	io.Copy(io.Discard, os.Stdin)
	return nil
}

func main() {
	if run() != nil {
		logEvent("ech_backend_failed", "", "configuration_or_runtime_error")
		os.Exit(1)
	}
}
