package main

import (
	"crypto/rsa"
	"encoding/hex"
	"fmt"

	"github.com/kubasiemion/x509PQexpansion/x509"
)

func CertString(c *x509.Certificate) string {
	s := "------CERTIFICATE--------\n"
	s += fmt.Sprintf("X509 Certifivate ver %v \nSerial No: %v\nIssued by: %s, %s/%s\nFor: %s\nSignature algorithm: %s\nKey algorithm: %v\nPublic Key: %s\nSignature: %s...\n",
		c.Version, c.SerialNumber, c.Issuer.Organization, c.Issuer.Locality, c.Issuer.Country,
		c.Subject, c.SignatureAlgorithm, c.PublicKeyAlgorithm, PubKeyString(c.PublicKey), hex.EncodeToString(c.Signature[:32]))
	return s
}

func PubKeyString(key interface{}) string {
	switch v := key.(type) {
	case *rsa.PublicKey:
		return RSAPubString(v)
	case *x509.PQPublicKey:
		return fmt.Sprintf("Algo: %s\n    Bytes: %s", v.OID.String(), hex.EncodeToString(v.RawBytes[:32]))
	default:
		return fmt.Sprint(key)
	}
}

func RSAPubString(rsa *rsa.PublicKey) string {
	return fmt.Sprintf("E: %v, N: %s....", rsa.E, hex.EncodeToString(rsa.N.Bytes()[:40]))
}

func PrCertChains(cca [][]*x509.Certificate) string {
	s := "=======================\n"
	s += "Certification hierarchy\n"
	s += fmt.Sprintf("Certification chains: %v\n", len(cca))
	for i, ca := range cca {
		s += fmt.Sprintf("Chain No: %v\n", i)
		for _, c := range ca {
			s += "------>\n"
			s += CertString(c)
		}

		s += "-----------------------\n"
	}
	s += "=======================\n"
	return s
}
