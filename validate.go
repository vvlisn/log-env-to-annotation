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
	// LogEnabledAnnotation 是启用日志收集的注解键。
	LogEnabledAnnotation = "co.elastic.logs/enabled"
	// LogEnabledValue 是启用日志收集的注解值。
	LogEnabledValue = "true"
	// RejectCode 是拒绝请求时使用的状态码。
	RejectCode = 400
)

// validate 是策略的入口函数。
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

// checkEnvVars 检查容器的环境变量并返回日志路径。
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

// getAnnotations 根据日志路径和设置生成注解。
func getAnnotations(logPaths []string, settings Settings) map[string]string {
	annotations := make(map[string]string)

	if len(logPaths) > 0 {
		// 设置基础注解
		annotations[settings.AnnotationBase] = logPaths[0]

		// 设置扩展注解
		if len(logPaths) > 1 && settings.AnnotationExtFormat != "" {
			for i, path := range logPaths[1:] {
				extKey := fmt.Sprintf(settings.AnnotationExtFormat, i+1)
				annotations[extKey] = path
			}
		}
	} else {
		annotations[LogEnabledAnnotation] = LogEnabledValue
	}

	// 添加额外的注解
	for key, value := range settings.AdditionalAnnotations {
		if value != nil {
			annotations[key] = convertToString(value)
		}
	}

	return annotations
}

// isDeploymentPod 检查 Pod 是否由 Deployment 创建。
func isDeploymentPod(pod *corev1.Pod) bool {
	if pod.Metadata == nil || len(pod.Metadata.OwnerReferences) == 0 {
		return false
	}

	// 检查是否由 ReplicaSet 创建
	for _, owner := range pod.Metadata.OwnerReferences {
		if owner != nil && *owner.Kind == "ReplicaSet" {
			return true
		}
	}
	return false
}

// handlePod 处理 Pod 资源的验证和变更。
func handlePod(request kubewarden_protocol.ValidationRequest, settings Settings) ([]byte, error) {
	// 解析原始对象
	var rawObj map[string]interface{}
	if err := json.Unmarshal(request.Request.Object, &rawObj); err != nil {
		return kubewarden.RejectRequest(kubewarden.Message(err.Error()), kubewarden.Code(RejectCode))
	}

	// 解析为 Pod 对象以便检查
	var pod corev1.Pod
	if err := json.Unmarshal(request.Request.Object, &pod); err != nil {
		return kubewarden.RejectRequest(kubewarden.Message(err.Error()), kubewarden.Code(RejectCode))
	}

	// 只处理由 Deployment 创建的 Pod
	if !isDeploymentPod(&pod) {
		return kubewarden.AcceptRequest()
	}

	// 检查第一个容器的环境变量
	var logPaths []string
	if len(pod.Spec.Containers) > 0 {
		logPaths = checkEnvVars(&pod.Spec.Containers[0], settings.EnvKey)
	}

	// 生成注解
	annotations := getAnnotations(logPaths, settings)

	// 更新原始对象的注解
	metadata, ok := rawObj["metadata"].(map[string]interface{})
	if !ok {
		metadata = make(map[string]interface{})
		rawObj["metadata"] = metadata
	}

	existingAnnotations, ok := metadata["annotations"].(map[string]interface{})
	if !ok {
		existingAnnotations = make(map[string]interface{})
	}

	// 合并注解
	for k, v := range annotations {
		existingAnnotations[k] = v
	}
	metadata["annotations"] = existingAnnotations

	return kubewarden.MutateRequest(rawObj)
}

// handleDeployment 处理 Deployment 资源的验证和变更。
func handleDeployment(request kubewarden_protocol.ValidationRequest, settings Settings) ([]byte, error) {
	// 解析原始对象
	var rawObj map[string]interface{}
	if err := json.Unmarshal(request.Request.Object, &rawObj); err != nil {
		return kubewarden.RejectRequest(kubewarden.Message(err.Error()), kubewarden.Code(RejectCode))
	}

	// 解析为 Deployment 对象以便检查
	var deployment appsv1.Deployment
	if err := json.Unmarshal(request.Request.Object, &deployment); err != nil {
		return kubewarden.RejectRequest(kubewarden.Message(err.Error()), kubewarden.Code(RejectCode))
	}

	if deployment.Spec == nil || deployment.Spec.Template.Spec == nil {
		return kubewarden.AcceptRequest()
	}

	// 检查第一个容器的环境变量
	var logPaths []string
	if len(deployment.Spec.Template.Spec.Containers) > 0 {
		logPaths = checkEnvVars(&deployment.Spec.Template.Spec.Containers[0], settings.EnvKey)
	}

	// 生成注解
	annotations := getAnnotations(logPaths, settings)

	// 更新原始对象的注解
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

	// 合并注解
	for k, v := range annotations {
		existingAnnotations[k] = v
	}
	metadata["annotations"] = existingAnnotations

	return kubewarden.MutateRequest(rawObj)
}

// convertToString 将任意类型转换为字符串。
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
