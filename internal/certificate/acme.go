package certificate

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/crypto/acme"
)

const ProductionDirectory = "https://acme-v02.api.letsencrypt.org/directory"
const StagingDirectory = "https://acme-staging-v02.api.letsencrypt.org/directory"

func accountKey(directory string) (*ecdsa.PrivateKey, error) {
	path := filepath.Join(directory, "account.key")
	if b, e := os.ReadFile(path); e == nil {
		block, _ := pem.Decode(b)
		if block == nil {
			return nil, errors.New("invalid private ACME account")
		}
		raw, e := x509.ParsePKCS8PrivateKey(block.Bytes)
		if e != nil {
			return nil, e
		}
		key, ok := raw.(*ecdsa.PrivateKey)
		if !ok {
			return nil, errors.New("invalid ACME account type")
		}
		return key, nil
	} else if !errors.Is(e, os.ErrNotExist) {
		return nil, e
	}
	key, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if e != nil {
		return nil, e
	}
	der, e := x509.MarshalPKCS8PrivateKey(key)
	if e != nil {
		return nil, e
	}
	if e = atomicFile(path, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), 0600); e != nil {
		return nil, e
	}
	return key, nil
}

// The CA and exact hostname are fixed by the local operator, never by an HTTP caller.
func ACME(host, directory, ca, email string) (Issuer, error) {
	if !Hostname(host) || (ca != ProductionDirectory && ca != StagingDirectory) {
		return nil, errors.New("unsupported certificate hostname or CA")
	}
	return func(ctx context.Context, present func(string, string) (func(), error)) ([]byte, []byte, error) {
		account, e := accountKey(directory)
		if e != nil {
			return nil, nil, e
		}
		transport := &http.Transport{Proxy: nil, MaxConnsPerHost: 1, MaxIdleConns: 1, MaxIdleConnsPerHost: 1, TLSHandshakeTimeout: 10 * time.Second, ResponseHeaderTimeout: 15 * time.Second}
		defer transport.CloseIdleConnections()
		client := &acme.Client{Key: account, DirectoryURL: ca, HTTPClient: &http.Client{Transport: transport, Timeout: 20 * time.Second}}
		return issueOrder(ctx, client, host, email, present)
	}, nil
}

func issueOrder(ctx context.Context, client *acme.Client, host, email string, present func(string, string) (func(), error)) ([]byte, []byte, error) {
	registration := &acme.Account{}
	if email != "" {
		registration.Contact = []string{"mailto:" + email}
	}
	if _, e := client.Register(ctx, registration, acme.AcceptTOS); e != nil && !errors.Is(e, acme.ErrAccountAlreadyExists) {
		return nil, nil, e
	}
	order, e := client.AuthorizeOrder(ctx, acme.DomainIDs(host))
	if e != nil {
		return nil, nil, e
	}
	for _, url := range order.AuthzURLs {
		a, e := client.GetAuthorization(ctx, url)
		if e != nil {
			return nil, nil, e
		}
		if a.Identifier.Type != "dns" || a.Identifier.Value != host {
			return nil, nil, errors.New("ACME authorization identity mismatch")
		}
		if a.Status == acme.StatusValid {
			continue
		}
		var challenge *acme.Challenge
		for _, c := range a.Challenges {
			if c.Type == "http-01" {
				challenge = c
				break
			}
		}
		if challenge == nil {
			return nil, nil, errors.New("HTTP-01 unavailable")
		}
		response, e := client.HTTP01ChallengeResponse(challenge.Token)
		if e != nil {
			return nil, nil, e
		}
		closeFn, e := present(challenge.Token, response)
		if e != nil {
			return nil, nil, e
		}
		_, e = client.Accept(ctx, challenge)
		if e == nil {
			_, e = client.WaitAuthorization(ctx, url)
		}
		closeFn()
		if e != nil {
			return nil, nil, e
		}
	}
	if _, e = client.WaitOrder(ctx, order.URI); e != nil {
		return nil, nil, e
	}
	key, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if e != nil {
		return nil, nil, e
	}
	csr, e := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: host}, DNSNames: []string{host}}, key)
	if e != nil {
		return nil, nil, e
	}
	certs, _, e := client.CreateOrderCert(ctx, order.FinalizeURL, csr, true)
	if e != nil || len(certs) == 0 || len(certs) > 8 {
		return nil, nil, errors.New("certificate issuance refused")
	}
	var fullchain []byte
	for _, der := range certs {
		if len(der) > 65536 {
			return nil, nil, errors.New("oversized certificate")
		}
		fullchain = append(fullchain, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})...)
	}
	der, e := x509.MarshalPKCS8PrivateKey(key)
	if e != nil {
		return nil, nil, e
	}
	return fullchain, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), nil
}
