package controller

import (
	"fmt"

	"github.com/go-logr/logr"
)

func contains(slice []string, s string) bool {
	for _, item := range slice {
		if item == s {
			return true
		}
	}
	return false
}

func remove(slice []string, s string) (result []string) {
	for _, item := range slice {
		if item == s {
			continue
		}
		result = append(result, item)
	}
	return
}

func LogAndReturnError(logger logr.Logger, format string, a ...any) error {
	ret := fmt.Errorf(format, a...)

	logger.Error(ret, format, a...)

	return ret
}
