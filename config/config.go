package config

import (
	"io/ioutil"
	"path"
	"path/filepath"
	"strings"

	"github.com/leanovate/microzon-auth-go/logging"
)

type Config struct {
	Server    *ServerConfig
	Store     *StoreConfig
	configDir string
}

func NewConfig(configDir string, logger logging.Logger) (*Config, error) {
	absoluteConfigDir, err := filepath.Abs(configDir)
	if err != nil {
		return nil, err
	}

	config := Config{
		Server:    NewServerConfig(),
		Store:     NewStoreConfig(logger),
		configDir: absoluteConfigDir,
	}
	files, err := ioutil.ReadDir(absoluteConfigDir)
	if err != nil {
		logger.Warnf("Read config failed (will use defaults): %s", err.Error())
		return &config, nil
	}
	for _, file := range files {
		switch {
		case !file.IsDir() && strings.HasPrefix(file.Name(), "server."):
			var err error
			config.Server, err = readServerConfig(path.Join(absoluteConfigDir, file.Name()))
			if err != nil {
				return nil, err
			}
		case !file.IsDir() && strings.HasPrefix(file.Name(), "store."):
			var err error
			config.Store, err = readStoreConfig(path.Join(absoluteConfigDir, file.Name()))
			if err != nil {
				return nil, err
			}
		}

	}

	return &config, nil
}
