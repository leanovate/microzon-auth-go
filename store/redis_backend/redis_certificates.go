package redis_backend

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"github.com/go-errors/errors"
	"time"
)

func certificateKey(ski string) string {
	return fmt.Sprintf("certificate:%s", ski)
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

func (r *redisStore) storeSelfCertificate() error {
	key := certificateKey(r.selfCertificate.Ski)
	value := encodeCert(r.selfCertificate.Certificate)
	expiration := r.selfCertificate.Certificate.NotAfter.Sub(time.Now())

	if err := r.redisClient.Set(key, value, expiration).Err(); err != nil {
		return errors.Wrap(err, 0)
	}
	return nil
}

func (r *redisStore) removeSelfCertificate() error {
	key := certificateKey(r.selfCertificate.Ski)
	if err := r.redisClient.Del(key).Err(); err != nil {
		return errors.Wrap(err, 0)
	}
	return nil
}

func (r *redisStore) scanCertificates() ([]*x509.Certificate, error) {
	result := make([]*x509.Certificate, 0)

	var cursor int64 = 0
	first := true
	for first || cursor != 0 {
		first = false
		nextCursor, keys, err := r.redisClient.Scan(cursor, certificateKey("*"), 0).Result()
		if err != nil {
			return nil, errors.Wrap(err, 0)
		}
		cursor = nextCursor
		encodedCerts, err := r.redisClient.MGet(keys...).Result()
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
	return result, nil
}

func (r *redisStore) getCertificateBySki(ski string) (*x509.Certificate, error) {
	encodedCert, err := r.redisClient.Get(certificateKey(ski)).Result()
	if err != nil {
		return nil, errors.Wrap(err, 0)

	}
	return decodeCert(encodedCert)
}
