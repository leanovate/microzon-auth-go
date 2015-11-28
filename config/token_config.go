package config

type TokenConfig struct {
	TokenTimeout uint32 `json:"token_timeout"`
}

func newTokenConfig() *TokenConfig {
	return &TokenConfig{
		TokenTimeout: 300,
	}
}

func readTokenConfig(fileName string) (*TokenConfig, error) {
	var tokenConfig TokenConfig

	if err := loadConfigFile(fileName, &tokenConfig); err != nil {
		return nil, err
	}

	return &tokenConfig, nil
}
