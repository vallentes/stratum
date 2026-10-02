package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Direct HTTPS by IP address, no domain or reverse proxy needed. The server makes a
// self-signed certificate once (kept in the data directory) for the listen IP. The
// browser warns once; collectors pin the certificate's SHA-256 fingerprint, which is
// baked into downloaded installers, so they verify the server without trusting a CA.

var tlsPin string // SHA-256 of the server certificate (hex), set when -tls-addr is used

func loadOrCreateCert(dataDir, addr string) (tls.Certificate, error) {
	certPath, keyPath := filepath.Join(dataDir, "tls-cert.pem"), filepath.Join(dataDir, "tls-key.pem")
	if c, err := tls.LoadX509KeyPair(certPath, keyPath); err == nil {
		return c, nil
	}
	host, _, _ := net.SplitHostPort(addr)
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 62))
	tpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "Stratum " + host, Organization: []string{"Stratum"}},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().AddDate(10, 0, 0),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"localhost"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	if ip := net.ParseIP(host); ip != nil && !ip.IsUnspecified() {
		tpl.IPAddresses = append(tpl.IPAddresses, ip)
	} else if host != "" {
		tpl.DNSNames = append(tpl.DNSNames, host)
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, err
	}
	kb, _ := x509.MarshalECPrivateKey(key)
	os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644)
	os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kb}), 0o600)
	return tls.LoadX509KeyPair(certPath, keyPath)
}

func certPin(c tls.Certificate) string {
	if len(c.Certificate) == 0 {
		return ""
	}
	h := sha256.Sum256(c.Certificate[0])
	return hex.EncodeToString(h[:])
}

// pinnedTLS trusts exactly the certificate with this fingerprint (and nothing else).
func pinnedTLS(pin string) *tls.Config {
	want, _ := hex.DecodeString(strings.ToLower(strings.ReplaceAll(pin, ":", "")))
	return &tls.Config{
		InsecureSkipVerify: true, // replaced by the exact-match check below
		VerifyPeerCertificate: func(raw [][]byte, _ [][]*x509.Certificate) error {
			if len(raw) == 0 {
				return errors.New("server sent no certificate")
			}
			h := sha256.Sum256(raw[0])
			if !bytes.Equal(h[:], want) {
				return errors.New("server certificate does not match the pinned fingerprint")
			}
			return nil
		},
	}
}
