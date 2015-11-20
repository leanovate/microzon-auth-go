package redis_backend

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"github.com/garyburd/redigo/redis"
	"github.com/go-errors/errors"
	"time"
)

func certificateKey(ski string) string {
	return fmt.Sprintf("certificate:%s", ski)
}

func encodeCert(certificate *x509.Certificate) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificate.Raw})
}

func decodeCert(reply interface{}, err error) (*x509.Certificate, error) {
	if reply == nil {
		return nil, nil
	}
	encodedCert, err := redis.Bytes(reply, err)
	if err != nil {
		return nil, errors.Wrap(err, 0)
	}
	certBlock, _ := pem.Decode(encodedCert)

	if certBlock.Type != "CERTIFICATE" {
		return nil, errors.Errorf("Invalid cert format")
	}

	return x509.ParseCertificate(certBlock.Bytes)
}

func (r *redisStore) storeSelfCertificate() error {
	conn := r.redisPool.Get()
	defer conn.Close()

	key := certificateKey(r.selfCertificate.Ski)
	value := encodeCert(r.selfCertificate.Certificate)
	ttl := int64(r.selfCertificate.Certificate.NotAfter.Sub(time.Now()) / time.Second)
	if _, err := conn.Do("SETEX", key, ttl, value); err != nil {
		return errors.Wrap(err, 0)
	}
	return nil
}

func (r *redisStore) removeSelfCertificate() error {
	conn := r.redisPool.Get()
	defer conn.Close()

	key := certificateKey(r.selfCertificate.Ski)
	if _, err := conn.Do("DEL", key); err != nil {
		return errors.Wrap(err, 0)
	}
	return nil
}

func (r *redisStore) scanCertificates() ([]*x509.Certificate, error) {
	conn := r.redisPool.Get()
	defer conn.Close()

	result := make([]*x509.Certificate, 0)

	nextChunk := 0
	first := true
	for first || nextChunk != 0 {
		first = false
		scanResult, err := redis.Values(conn.Do("SCAN", nextChunk, "MATCH", certificateKey("*")))
		if err != nil {
			return nil, errors.Wrap(err, 0)
		}
		var keys []string
		if _, err := redis.Scan(scanResult, &nextChunk, &keys); err != nil {
			return nil, errors.Wrap(err, 0)
		}
		for _, key := range keys {
			cert, err := decodeCert(conn.Do("GET", key))
			if err != nil {
				return nil, errors.Wrap(err, 0)
			}
			if cert != nil {
				result = append(result, cert)
			}
		}
	}
	return result, nil
}

func (r *redisStore) getCertificateBySki(ski string) (*x509.Certificate, error) {
	conn := r.redisPool.Get()
	defer conn.Close()

	return decodeCert(conn.Do("GET", certificateKey(ski)))
}
