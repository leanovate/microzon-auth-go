package redis_backend

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"github.com/go-errors/errors"
	"gopkg.in/redis.v3"
	"time"
)

func certificateKey(x5t string) string {
	return fmt.Sprintf("certificate:%s", x5t)
}

func encodeCert(certificate *x509.Certificate) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificate.Raw})
}

func decodeCert(encoded string) (*x509.Certificate, error) {
	certBlock, _ := pem.Decode([]byte(encoded))

	if certBlock.Type != "CERTIFICATE" {
		return nil, errors.Errorf("Invalid cert format")
	}

	return x509.ParseCertificate(certBlock.Bytes)
}

func (r *redisStore) AddCertificate(thumbprint string, certificate *x509.Certificate) error {
	key := certificateKey(thumbprint)
	value := encodeCert(certificate)
	expiration := certificate.NotAfter.Sub(time.Now())

	client, err := r.connector.getClient(key)
	if err != nil {
		return errors.Wrap(err, 0)
	}
	if err := client.Set(key, value, expiration).Err(); err != nil {
		return errors.Wrap(err, 0)
	}
	return nil
}

func (r *redisStore) RemoveCertificate(thumbprint string) error {
	key := certificateKey(thumbprint)
	client, err := r.connector.getClient(key)
	if err != nil {
		return errors.Wrap(err, 0)
	}
	if err := client.Del(key).Err(); err != nil {
		return errors.Wrap(err, 0)
	}
	return nil
}

func (r *redisStore) scanCertificates() ([]*x509.Certificate, error) {
	result := make([]*x509.Certificate, 0)

	client, err := r.connector.getClient("")
	if err != nil {
		return nil, errors.Wrap(err, 0)
	}
	var cursor int64 = 0
	first := true
	for first || cursor != 0 {
		first = false
		nextCursor, keys, err := client.Scan(cursor, certificateKey("*"), 0).Result()
		if err != nil {
			return nil, errors.Wrap(err, 0)
		}
		cursor = nextCursor
		if len(keys) > 0 {
			encodedCerts, err := client.MGet(keys...).Result()
			if err != nil {
				return nil, errors.Wrap(err, 0)
			}
			for _, encodedCert := range encodedCerts {
				cert, err := decodeCert(encodedCert.(string))
				if err != nil {
					r.logger.Warn("Invalid cert in database")
				}
				result = append(result, cert)
			}
		}
	}
	return result, nil
}

func (r *redisStore) getCertificateByX5t(ski string) (*x509.Certificate, error) {
	key := certificateKey(ski)
	client, err := r.connector.getClient(key)
	if err != nil {
		return nil, errors.Wrap(err, 0)
	}
	encodedCert, err := client.Get(key).Result()
	if err == redis.Nil {
		return nil, nil
	}
	if err != nil {
		return nil, errors.Wrap(err, 0)

	}
	return decodeCert(encodedCert)
}
