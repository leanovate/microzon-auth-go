package config

import "time"

type TokenConfig struct {
	TokenTTL time.Duration `json:"token_ttl" yaml:"token_ttl"`
}

func newTokenConfig() *TokenConfig {
	return &TokenConfig{
		TokenTTL: 5 * time.Minute,
	}
}

func readTokenConfig(fileName string) (*TokenConfig, error) {
	var tokenConfig TokenConfig

	if err := loadConfigFile(fileName, &tokenConfig); err != nil {
		return nil, err
	}

	return &tokenConfig, nil
}
