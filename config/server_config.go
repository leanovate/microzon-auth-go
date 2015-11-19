package config

type ServerConfig struct {
	BindAddress string `json:"bindAddress" yaml:"bindAddress"`
	HttpPort    int    `json:"httpPort" yaml:"httpPort"`
}

func NewServerConfig() *ServerConfig {
	return &ServerConfig{
		BindAddress: "0.0.0.0",
		HttpPort:    8080,
	}
}

func readServerConfig(fileName string) (*ServerConfig, error) {
	var serverConfig ServerConfig

	if err := loadConfigFile(fileName, &serverConfig); err != nil {
		return nil, err
	}

	return &serverConfig, nil
}
