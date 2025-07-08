package main

import (
	"encoding/json"
	"fmt"
	"strconv"

	corev1 "github.com/kubewarden/k8s-objects/api/core/v1"
	metav1 "github.com/kubewarden/k8s-objects/apimachinery/pkg/apis/meta/v1"
	kubewarden "github.com/kubewarden/policy-sdk-go"
	kubewarden_protocol "github.com/kubewarden/policy-sdk-go/protocol"
)

const RejectCode = 400

// validate 是入口函数.
func validate(payload []byte) ([]byte, error) {
	var validationRequest kubewarden_protocol.ValidationRequest
	if err := json.Unmarshal(payload, &validationRequest); err != nil {
		return kubewarden.RejectRequest(kubewarden.Message(err.Error()), kubewarden.Code(RejectCode))
	}

	settings, err := NewSettingsFromValidationReq(&validationRequest)
	if err != nil {
		return kubewarden.RejectRequest(kubewarden.Message(err.Error()), kubewarden.Code(RejectCode))
	}

	return processPod(validationRequest, settings)
}

// processPod 处理 Pod 类型的资源.
func processPod(req kubewarden_protocol.ValidationRequest, settings Settings) ([]byte, error) {
	if req.Request.Kind.Kind != "Pod" {
		return kubewarden.AcceptRequest()
	}

	var pod corev1.Pod
	if err := json.Unmarshal(req.Request.Object, &pod); err != nil {
		return kubewarden.RejectRequest(kubewarden.Message("cannot unmarshal pod"), kubewarden.Code(RejectCode))
	}

	mutated := mutatePodContainers(&pod, settings)

	if !mutated {
		return kubewarden.AcceptRequest()
	}

	return kubewarden.MutateRequest(pod)
}

func mutatePodContainers(pod *corev1.Pod, settings Settings) bool {
	mutated := false
	if pod.Metadata == nil {
		pod.Metadata = &metav1.ObjectMeta{}
	}
	if pod.Metadata.Annotations == nil {
		pod.Metadata.Annotations = map[string]string{}
	}

	if len(pod.Spec.Containers) > 0 {
		if processContainerEnv(
			pod.Spec.Containers[0],
			pod.Metadata.Annotations,
			settings,
		) {
			mutated = true
		}
	}

	// 添加自定义注解的条件判断
	envExists := false
	if len(pod.Spec.Containers) > 0 {
		for _, env := range pod.Spec.Containers[0].Env {
			if env != nil && env.Name != nil && *env.Name == settings.EnvKey {
				envExists = true
				break
			}
		}
	}

	if envExists && settings.AdditionalAnnotations != nil {
		for key, value := range settings.AdditionalAnnotations {
			if value != nil {
				// 调用类型转换函数
				strValue := convertToString(value)
				pod.Metadata.Annotations[key] = strValue
				mutated = true
			}
		}
	}

	return mutated
}

func processContainerEnv(container *corev1.Container, annotations map[string]string, settings Settings) bool {
	if container == nil {
		return false
	}
	var logPaths []string
	for _, env := range container.Env {
		if env == nil || env.Name == nil {
			continue
		}
		if *env.Name == settings.EnvKey {
			logPaths = append(logPaths, env.Value)
		}
	}

	if len(logPaths) > 0 {
		if container.Name == nil {
			return false
		}
		for i, path := range logPaths {
			var annotationKey string
			if i == 0 {
				annotationKey = settings.AnnotationBase
			} else {
				annotationKey = fmt.Sprintf(settings.AnnotationExtFormat, i)
			}
			annotations[annotationKey] = path
		}
		return true
	}
	return false
}

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
