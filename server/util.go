package server

import (
	"net/http"
	"strconv"
)

func queryParamUint(req *http.Request, key string, defaultValue uint64) (uint64, error) {
	value := req.FormValue(key)
	if value == "" {
		return defaultValue, nil
	}
	return strconv.ParseUint(value, 10, 64)
}
