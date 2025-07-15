package main

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	appsv1 "github.com/kubewarden/k8s-objects/api/apps/v1"
	corev1 "github.com/kubewarden/k8s-objects/api/core/v1"
	kubewarden "github.com/kubewarden/policy-sdk-go"
	kubewarden_protocol "github.com/kubewarden/policy-sdk-go/protocol"
)

const (
	// LogEnabledAnnotation is the annotation key to enable log collection.
	LogEnabledAnnotation = "co.elastic.logs/enabled"
	// LogEnabledValue is the annotation value to enable log collection.
	LogEnabledValue = "true"
	// RejectCode is the status code used when rejecting a request.
	RejectCode = 400
)

// validate is the entry point of the policy.
func validate(payload []byte) ([]byte, error) {
	var validationRequest kubewarden_protocol.ValidationRequest
	if err := json.Unmarshal(payload, &validationRequest); err != nil {
		return kubewarden.RejectRequest(kubewarden.Message(err.Error()), kubewarden.Code(RejectCode))
	}

	settings, err := NewSettingsFromValidationReq(&validationRequest)
	if err != nil {
		return kubewarden.RejectRequest(kubewarden.Message(err.Error()), kubewarden.Code(RejectCode))
	}

	switch strings.ToLower(validationRequest.Request.Kind.Kind) {
	case "pod":
		return handlePod(validationRequest, settings)
	case "deployment":
		return handleDeployment(validationRequest, settings)
	default:
		return kubewarden.AcceptRequest()
	}
}

// checkEnvVars checks the environment variables of a container and returns the log paths.
func checkEnvVars(container **corev1.Container, envKey string) []string {
	if container == nil || *container == nil {
		return nil
	}

	var logPaths []string
	for _, env := range (*container).Env {
		if env != nil && env.Name != nil && *env.Name == envKey {
			logPaths = append(logPaths, env.Value)
		}
	}
	return logPaths
}

// getAnnotations generates annotations based on log paths and settings.
func getAnnotations(logPaths []string, settings Settings) map[string]string {
	annotations := make(map[string]string)

	if len(logPaths) > 0 {
		// Set base annotation
		annotations[settings.AnnotationBase] = logPaths[0]

		// Set extended annotations
		if len(logPaths) > 1 && settings.AnnotationExtFormat != "" {
			for i, path := range logPaths[1:] {
				extKey := fmt.Sprintf(settings.AnnotationExtFormat, i+1)
				annotations[extKey] = path
			}
		}
	} else {
		annotations[LogEnabledAnnotation] = LogEnabledValue
	}

	// Add additional annotations
	for key, value := range settings.AdditionalAnnotations {
		if value != nil {
			annotations[key] = convertToString(value)
		}
	}

	return annotations
}

// isDeploymentPod checks if a Pod was created by a Deployment.
func isDeploymentPod(pod *corev1.Pod) bool {
	if pod.Metadata == nil || len(pod.Metadata.OwnerReferences) == 0 {
		return false
	}

	// Check if it was created by a ReplicaSet
	for _, owner := range pod.Metadata.OwnerReferences {
		if owner != nil && *owner.Kind == "ReplicaSet" {
			return true
		}
	}
	return false
}

// handlePod handles the validation and mutation of Pod resources.
func handlePod(request kubewarden_protocol.ValidationRequest, settings Settings) ([]byte, error) {
	// Unmarshal the original object
	var rawObj map[string]interface{}
	if err := json.Unmarshal(request.Request.Object, &rawObj); err != nil {
		return kubewarden.RejectRequest(kubewarden.Message(err.Error()), kubewarden.Code(RejectCode))
	}

	// Unmarshal to a Pod object for checking
	var pod corev1.Pod
	if err := json.Unmarshal(request.Request.Object, &pod); err != nil {
		return kubewarden.RejectRequest(kubewarden.Message(err.Error()), kubewarden.Code(RejectCode))
	}

	// Only handle Pods created by a Deployment
	if !isDeploymentPod(&pod) {
		return kubewarden.AcceptRequest()
	}

	// Check the environment variables of the first container
	var logPaths []string
	if len(pod.Spec.Containers) > 0 {
		logPaths = checkEnvVars(&pod.Spec.Containers[0], settings.EnvKey)
	}

	// Generate annotations
	annotations := getAnnotations(logPaths, settings)

	// Update the annotations of the original object
	metadata, ok := rawObj["metadata"].(map[string]interface{})
	if !ok {
		metadata = make(map[string]interface{})
		rawObj["metadata"] = metadata
	}

	existingAnnotations, ok := metadata["annotations"].(map[string]interface{})
	if !ok {
		existingAnnotations = make(map[string]interface{})
	}

	// Merge annotations
	for k, v := range annotations {
		existingAnnotations[k] = v
	}
	metadata["annotations"] = existingAnnotations

	return kubewarden.MutateRequest(rawObj)
}

// handleDeployment handles the validation and mutation of Deployment resources.
func handleDeployment(request kubewarden_protocol.ValidationRequest, settings Settings) ([]byte, error) {
	// Unmarshal the original object
	var rawObj map[string]interface{}
	if err := json.Unmarshal(request.Request.Object, &rawObj); err != nil {
		return kubewarden.RejectRequest(kubewarden.Message(err.Error()), kubewarden.Code(RejectCode))
	}

	// Unmarshal to a Deployment object for checking
	var deployment appsv1.Deployment
	if err := json.Unmarshal(request.Request.Object, &deployment); err != nil {
		return kubewarden.RejectRequest(kubewarden.Message(err.Error()), kubewarden.Code(RejectCode))
	}

	if deployment.Spec == nil || deployment.Spec.Template.Spec == nil {
		return kubewarden.AcceptRequest()
	}

	// Check the environment variables of the first container
	var logPaths []string
	if len(deployment.Spec.Template.Spec.Containers) > 0 {
		logPaths = checkEnvVars(&deployment.Spec.Template.Spec.Containers[0], settings.EnvKey)
	}

	// Generate annotations
	annotations := getAnnotations(logPaths, settings)

	// Update the annotations of the original object
	spec, ok := rawObj["spec"].(map[string]interface{})
	if !ok {
		return kubewarden.RejectRequest(kubewarden.Message("Invalid deployment spec"), kubewarden.Code(RejectCode))
	}

	template, ok := spec["template"].(map[string]interface{})
	if !ok {
		return kubewarden.RejectRequest(kubewarden.Message("Invalid deployment template"), kubewarden.Code(RejectCode))
	}

	metadata, ok := template["metadata"].(map[string]interface{})
	if !ok {
		metadata = make(map[string]interface{})
		template["metadata"] = metadata
	}

	existingAnnotations, ok := metadata["annotations"].(map[string]interface{})
	if !ok {
		existingAnnotations = make(map[string]interface{})
	}

	// Merge annotations
	for k, v := range annotations {
		existingAnnotations[k] = v
	}
	metadata["annotations"] = existingAnnotations

	return kubewarden.MutateRequest(rawObj)
}

// convertToString converts any type to a string.
func convertToString(value interface{}) string {
	switch v := value.(type) {
	case string:
		return v
	case bool:
		return strconv.FormatBool(v)
	case int, int32, int64:
		return fmt.Sprintf("%d", v)
	case float32, float64:
		return fmt.Sprintf("%f", v)
	default:
		return fmt.Sprintf("%v", v)
	}
}
