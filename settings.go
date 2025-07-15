package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	kubewarden "github.com/kubewarden/policy-sdk-go"
	kubewarden_protocol "github.com/kubewarden/policy-sdk-go/protocol"
)

// Settings defines all the configurable options of the policy.
type Settings struct {
	// EnvKey is the container environment variable name to match for conversion.
	EnvKey string `json:"env_key"`
	// AnnotationBase is the base annotation key for the first log path.
	AnnotationBase string `json:"annotation_base"`
	// AnnotationExtFormat is the extended annotation key format for subsequent log paths.
	// Format: co_elastic_logs_path_ext_%d, where %d is replaced by the sequence number 1, 2, 3...
	AnnotationExtFormat string `json:"annotation_ext_format"`
	// AdditionalAnnotations are custom key-value pairs for annotations.
	AdditionalAnnotations map[string]interface{} `json:"additional_annotations,omitempty"`
}

// NewSettingsFromValidationReq extracts settings from a ValidationRequest.
func NewSettingsFromValidationReq(validationReq *kubewarden_protocol.ValidationRequest) (Settings, error) {
	settings := Settings{}
	err := json.Unmarshal(validationReq.Settings, &settings)
	return settings, err
}

// Valid validates the settings.
func (s *Settings) Valid() (bool, error) {
	if s.EnvKey == "" {
		return false, errors.New("env_key cannot be empty")
	}
	if s.AnnotationBase == "" {
		return false, errors.New("annotation_base cannot be empty")
	}
	if s.AnnotationExtFormat == "" {
		return false, errors.New("annotation_ext_format cannot be empty")
	}

	// Validate AdditionalAnnotations key-value pairs
	if s.AdditionalAnnotations != nil {
		for key, value := range s.AdditionalAnnotations {
			if key == "" {
				return false, errors.New("additional_annotations keys cannot be empty")
			}
			// Allow boolean, numeric, and other non-string types
			// Only check for emptiness if the value is a string
			if strVal, ok := value.(string); ok {
				if strVal == "" {
					return false, errors.New("additional_annotations string values cannot be empty")
				}
			}
		}
	}

	// Validate that AnnotationExtFormat contains the %d placeholder
	if !strings.Contains(s.AnnotationExtFormat, "%d") {
		return false, errors.New("annotation_ext_format must contain %d placeholder")
	}
	return true, nil
}

// validateSettings is called by Kubewarden when the policy is loaded.
func validateSettings(payload []byte) ([]byte, error) {
	logger.Info("validating settings")

	settings := Settings{}
	err := json.Unmarshal(payload, &settings)
	if err != nil {
		return kubewarden.RejectSettings(kubewarden.Message(fmt.Sprintf("Provided settings are not valid: %v", err)))
	}

	valid, err := settings.Valid()
	if err != nil {
		return kubewarden.RejectSettings(kubewarden.Message(fmt.Sprintf("Provided settings are not valid: %v", err)))
	}
	if valid {
		return kubewarden.AcceptSettings()
	}

	logger.Warn("rejecting settings")
	return kubewarden.RejectSettings(kubewarden.Message("Provided settings are not valid"))
}
