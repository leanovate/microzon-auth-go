package config

type TokenConfig struct {
	TokenTTL uint32 `json:"token_ttl" yaml:"token_ttl"`
}

func newTokenConfig() *TokenConfig {
	return &TokenConfig{
		TokenTTL: 300,
	}
}

func readTokenConfig(fileName string) (*TokenConfig, error) {
	var tokenConfig TokenConfig

	if err := loadConfigFile(fileName, &tokenConfig); err != nil {
		return nil, err
	}

	return &tokenConfig, nil
}
