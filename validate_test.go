package main

import (
	"encoding/json"
	"strings"
	"testing"

	corev1 "github.com/kubewarden/k8s-objects/api/core/v1"
	metav1 "github.com/kubewarden/k8s-objects/apimachinery/pkg/apis/meta/v1"
	kubewarden_protocol "github.com/kubewarden/policy-sdk-go/protocol"
)

// validateTest 是一个辅助函数，用于执行策略验证。
func validateTest(
	t *testing.T,
	request kubewarden_protocol.ValidationRequest,
) (*kubewarden_protocol.ValidationResponse, error) {
	t.Helper()

	payload, err := json.Marshal(request)
	if err != nil {
		return nil, err
	}

	responsePayload, err := validate(payload)
	if err != nil {
		return nil, err
	}

	var response kubewarden_protocol.ValidationResponse
	if unmarshalErr := json.Unmarshal(responsePayload, &response); unmarshalErr != nil {
		return nil, unmarshalErr
	}

	return &response, nil
}

func TestPodMutation(t *testing.T) {
	tests := []struct {
		name                string
		settings            Settings
		pod                 corev1.Pod
		expectedAnnotations map[string]string
		shouldMutate        bool
	}{
		{
			name: "pod with securityContext",
			settings: Settings{
				EnvKey:         "LOG_PATH",
				AnnotationBase: "co_elastic_logs_path",
			},
			pod: corev1.Pod{
				Spec: &corev1.PodSpec{
					SecurityContext: &corev1.PodSecurityContext{
						RunAsUser:  1000,
						RunAsGroup: 1000,
					},
					Containers: []*corev1.Container{
						{
							Name: stringPtr("my-container"),
							Env: []*corev1.EnvVar{
								{
									Name:  stringPtr("LOG_PATH"),
									Value: "/var/log/app.log",
								},
							},
							SecurityContext: &corev1.SecurityContext{
								Privileged: false,
								RunAsUser:  0,
							},
						},
					},
				},
				Metadata: &metav1.ObjectMeta{
					OwnerReferences: []*metav1.OwnerReference{
						{
							APIVersion: stringPtr("apps/v1"),
							Kind:       stringPtr("ReplicaSet"),
							Name:       stringPtr("test-rs"),
							UID:        stringPtr("test-uid"),
						},
					},
				},
			},
			expectedAnnotations: map[string]string{
				"co_elastic_logs_path": "/var/log/app.log",
			},
			shouldMutate: true,
		},
		{
			name: "pod with single container and target env",
			settings: Settings{
				EnvKey:         "LOG_PATH",
				AnnotationBase: "co_elastic_logs_path",
			},
			pod: corev1.Pod{
				Spec: &corev1.PodSpec{
					Containers: []*corev1.Container{
						{
							Name: stringPtr("my-container"),
							Env: []*corev1.EnvVar{
								{
									Name:  stringPtr("LOG_PATH"),
									Value: "/var/log/app.log",
								},
							},
						},
					},
				},
				Metadata: &metav1.ObjectMeta{
					OwnerReferences: []*metav1.OwnerReference{
						{
							APIVersion: stringPtr("apps/v1"),
							Kind:       stringPtr("ReplicaSet"),
							Name:       stringPtr("test-rs"),
							UID:        stringPtr("test-uid"),
						},
					},
				},
			},
			expectedAnnotations: map[string]string{
				"co_elastic_logs_path": "/var/log/app.log",
			},
			shouldMutate: true,
		},
		{
			name: "pod with no target env",
			settings: Settings{
				EnvKey:         "LOG_PATH",
				AnnotationBase: "co_elastic_logs_path",
			},
			pod: corev1.Pod{
				Metadata: &metav1.ObjectMeta{
					OwnerReferences: []*metav1.OwnerReference{
						{
							APIVersion: stringPtr("apps/v1"),
							Kind:       stringPtr("ReplicaSet"),
							Name:       stringPtr("test-rs"),
							UID:        stringPtr("test-uid"),
						},
					},
				},
				Spec: &corev1.PodSpec{
					Containers: []*corev1.Container{
						{
							Name: stringPtr("my-container"),
							Env: []*corev1.EnvVar{
								{
									Name:  stringPtr("OTHER_ENV"),
									Value: "some_value",
								},
							},
						},
					},
				},
			},
			expectedAnnotations: map[string]string{
				"co.elastic.logs/enabled": "true",
			},
			shouldMutate: true,
		},
		{
			name: "pod with additional annotations",
			settings: Settings{
				EnvKey:         "LOG_PATH",
				AnnotationBase: "co_elastic_logs_path",
				AdditionalAnnotations: map[string]interface{}{
					"custom.annotation/key1": "value1",
					"custom.annotation/key2": "value2",
				},
			},
			pod: corev1.Pod{
				Metadata: &metav1.ObjectMeta{
					OwnerReferences: []*metav1.OwnerReference{
						{
							APIVersion: stringPtr("apps/v1"),
							Kind:       stringPtr("ReplicaSet"),
							Name:       stringPtr("test-rs"),
							UID:        stringPtr("test-uid"),
						},
					},
				},
				Spec: &corev1.PodSpec{
					Containers: []*corev1.Container{
						{
							Name: stringPtr("my-container"),
							Env: []*corev1.EnvVar{
								{
									Name:  stringPtr("LOG_PATH"),
									Value: "/var/log/app.log",
								},
							},
						},
					},
				},
			},
			expectedAnnotations: map[string]string{
				"co_elastic_logs_path":   "/var/log/app.log",
				"custom.annotation/key1": "value1",
				"custom.annotation/key2": "value2",
			},
			shouldMutate: true,
		},
		{
			name: "pod not owned by replicaset",
			settings: Settings{
				EnvKey:         "LOG_PATH",
				AnnotationBase: "co_elastic_logs_path",
			},
			pod: corev1.Pod{
				Spec: &corev1.PodSpec{
					Containers: []*corev1.Container{
						{
							Name: stringPtr("my-container"),
							Env: []*corev1.EnvVar{
								{
									Name:  stringPtr("LOG_PATH"),
									Value: "/var/log/app.log",
								},
							},
						},
					},
				},
				Metadata: &metav1.ObjectMeta{},
			},
			expectedAnnotations: nil,
			shouldMutate:        false,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			runTest(t, test)
		})
	}
}

func TestWorkloadMutation(t *testing.T) {
	settings := Settings{
		EnvKey:         "LOG_PATH",
		AnnotationBase: "co_elastic_logs_path",
	}

	// 创建一个带有 securityContext 的 Deployment
	workload := map[string]interface{}{
		"apiVersion": "apps/v1",
		"kind":       "Deployment",
		"metadata": map[string]interface{}{
			"name": "test-deployment",
		},
		"spec": map[string]interface{}{
			"template": map[string]interface{}{
				"spec": map[string]interface{}{
					"securityContext": map[string]interface{}{
						"runAsUser":  1000,
						"runAsGroup": 1000,
					},
					"containers": []map[string]interface{}{
						{
							"name":  "test-container",
							"image": "nginx:latest",
							"env": []map[string]interface{}{
								{
									"name":  "LOG_PATH",
									"value": "/var/log/app.log",
								},
							},
						},
					},
				},
			},
		},
	}

	request := kubewarden_protocol.ValidationRequest{
		Request: kubewarden_protocol.KubernetesAdmissionRequest{
			Object: mustMarshalJSON(workload),
			Kind: kubewarden_protocol.GroupVersionKind{
				Kind: "Deployment",
			},
		},
		Settings: mustMarshalJSON(settings),
	}

	response, err := validateTest(t, request)
	if err != nil {
		t.Fatalf("Validation failed: %v", err)
	}

	if !response.Accepted {
		t.Error("Expected request to be accepted")
		return
	}

	if response.MutatedObject == nil {
		t.Error("Expected mutation but got none")
		return
	}

	var mutatedWorkload map[string]interface{}
	mutatedJSON := mustMarshalJSON(response.MutatedObject)
	if unmarshalErr := json.Unmarshal(mutatedJSON, &mutatedWorkload); unmarshalErr != nil {
		t.Fatalf("Failed to unmarshal mutated object: %v", unmarshalErr)
	}

	// 验证 securityContext 是否保留
	template := mutatedWorkload["spec"].(map[string]interface{})["template"].(map[string]interface{})
	spec := template["spec"].(map[string]interface{})
	if _, hasSecurityContext := spec["securityContext"]; !hasSecurityContext {
		t.Error("Expected securityContext to be preserved")
	}

	// 验证注解
	metadata := template["metadata"].(map[string]interface{})
	annotations := metadata["annotations"].(map[string]interface{})

	expectedValue := "/var/log/app.log"
	if actualValue, ok := annotations["co_elastic_logs_path"].(string); !ok || actualValue != expectedValue {
		t.Errorf("Expected annotation co_elastic_logs_path to be %s, got %v",
			expectedValue, annotations["co_elastic_logs_path"])
	}
}

func TestObjectIntegrity(t *testing.T) {
	settings := Settings{
		EnvKey:         "LOG_PATH",
		AnnotationBase: "co_elastic_logs_path",
	}

	// 创建一个完整的 Pod 对象
	originalPod := map[string]interface{}{
		"apiVersion": "v1",
		"kind":       "Pod",
		"metadata": map[string]interface{}{
			"name": "test-pod",
			"ownerReferences": []interface{}{
				map[string]interface{}{
					"apiVersion": "apps/v1",
					"kind":       "ReplicaSet",
					"name":       "test-rs",
					"uid":        "test-uid",
				},
			},
		},
		"spec": map[string]interface{}{
			"securityContext": map[string]interface{}{
				"runAsUser":  1000,
				"runAsGroup": 1000,
			},
			"containers": []interface{}{
				map[string]interface{}{
					"name":  "test-container",
					"image": "nginx:latest",
					"env": []interface{}{
						map[string]interface{}{
							"name":  "LOG_PATH",
							"value": "/var/log/app.log",
						},
					},
					"securityContext": map[string]interface{}{
						"privileged": false,
						"runAsUser":  0,
					},
				},
			},
		},
	}

	request := kubewarden_protocol.ValidationRequest{
		Request: kubewarden_protocol.KubernetesAdmissionRequest{
			Object: mustMarshalJSON(originalPod),
			Kind: kubewarden_protocol.GroupVersionKind{
				Kind: "Pod",
			},
		},
		Settings: mustMarshalJSON(settings),
	}

	response, err := validateTest(t, request)
	if err != nil {
		t.Fatalf("Validation failed: %v", err)
	}

	if !response.Accepted {
		t.Error("Expected request to be accepted")
		return
	}

	if response.MutatedObject == nil {
		t.Error("Expected mutation but got none")
		return
	}

	// 将原始对象和变更后的对象转换为 JSON 字符串进行比较
	originalJSON := mustMarshalJSON(originalPod)
	mutatedJSON := mustMarshalJSON(response.MutatedObject)

	var original, mutated map[string]interface{}
	if err := json.Unmarshal(originalJSON, &original); err != nil {
		t.Fatalf("Failed to unmarshal original object: %v", err)
	}
	if err := json.Unmarshal(mutatedJSON, &mutated); err != nil {
		t.Fatalf("Failed to unmarshal mutated object: %v", err)
	}

	// 验证除了注解之外的所有字段都保持不变
	assertObjectsEqual(t, original, mutated, []string{"metadata", "metadata.annotations"})
}

// assertObjectsEqual 递归比较两个对象，忽略指定的路径
func assertObjectsEqual(t *testing.T, original, mutated map[string]interface{}, ignorePaths []string) {
	t.Helper()

	for key, originalValue := range original {
		// 跳过被忽略的路径
		if contains(ignorePaths, key) {
			continue
		}

		mutatedValue, exists := mutated[key]
		if !exists {
			t.Errorf("Field %s was removed", key)
			continue
		}

		switch v := originalValue.(type) {
		case map[string]interface{}:
			if mv, ok := mutatedValue.(map[string]interface{}); ok {
				// 构建新的忽略路径
				newIgnorePaths := make([]string, 0)
				for _, path := range ignorePaths {
					if strings.HasPrefix(path, key+".") {
						newPath := strings.TrimPrefix(path, key+".")
						newIgnorePaths = append(newIgnorePaths, newPath)
					}
				}
				assertObjectsEqual(t, v, mv, newIgnorePaths)
			} else {
				t.Errorf("Field %s type changed from map to %T", key, mutatedValue)
			}
		case []interface{}:
			if mv, ok := mutatedValue.([]interface{}); ok {
				if len(v) != len(mv) {
					t.Errorf("Field %s array length changed from %d to %d", key, len(v), len(mv))
				} else {
					for i := range v {
						if vm1, ok1 := v[i].(map[string]interface{}); ok1 {
							if vm2, ok2 := mv[i].(map[string]interface{}); ok2 {
								assertObjectsEqual(t, vm1, vm2, ignorePaths)
							}
						} else if v[i] != mv[i] {
							t.Errorf("Field %s[%d] value changed from %v to %v", key, i, v[i], mv[i])
						}
					}
				}
			} else {
				t.Errorf("Field %s type changed from array to %T", key, mutatedValue)
			}
		default:
			if originalValue != mutatedValue {
				t.Errorf("Field %s value changed from %v to %v", key, originalValue, mutatedValue)
			}
		}
	}

	// 检查是否添加了新字段
	for key := range mutated {
		if _, exists := original[key]; !exists && !contains(ignorePaths, key) {
			t.Errorf("Unexpected field added: %s", key)
		}
	}
}

func contains(slice []string, str string) bool {
	for _, s := range slice {
		if s == str {
			return true
		}
	}
	return false
}

func runTest(t *testing.T, test struct {
	name                string
	settings            Settings
	pod                 corev1.Pod
	expectedAnnotations map[string]string
	shouldMutate        bool
}) {
	t.Helper()

	podJSON := mustMarshalJSON(test.pod)
	settingsJSON := mustMarshalJSON(test.settings)

	req := kubewarden_protocol.ValidationRequest{
		Request: kubewarden_protocol.KubernetesAdmissionRequest{
			Kind: kubewarden_protocol.GroupVersionKind{
				Kind: "Pod",
			},
			Object: podJSON,
		},
		Settings: settingsJSON,
	}

	response, err := validateTest(t, req)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	if !response.Accepted {
		t.Error("Expected request to be accepted")
	}

	if test.shouldMutate {
		assertMutation(t, response, test.expectedAnnotations)
	} else {
		assertNoMutation(t, response)
	}
}

func assertMutation(
	t *testing.T,
	response *kubewarden_protocol.ValidationResponse,
	expectedAnnotations map[string]string,
) {
	t.Helper()

	if response.MutatedObject == nil {
		t.Error("Expected mutation but got none")
		return
	}

	var mutatedPod map[string]interface{}
	mutatedJSON := mustMarshalJSON(response.MutatedObject)
	if err := json.Unmarshal(mutatedJSON, &mutatedPod); err != nil {
		t.Fatalf("Failed to unmarshal mutated object: %v", err)
	}

	// 验证注解
	metadata, ok := mutatedPod["metadata"].(map[string]interface{})
	if !ok {
		t.Error("Expected metadata in mutated pod")
		return
	}

	annotations, ok := metadata["annotations"].(map[string]interface{})
	if !ok {
		t.Error("Expected annotations in mutated pod")
		return
	}

	for key, expectedValue := range expectedAnnotations {
		if actualValue, ok := annotations[key].(string); !ok || actualValue != expectedValue {
			t.Errorf("Expected annotation %s to be %s, got %v",
				key, expectedValue, annotations[key])
		}
	}

	// 检查是否有意外的注解
	for key := range annotations {
		if _, expected := expectedAnnotations[key]; !expected {
			t.Errorf("Unexpected annotation found: %s", key)
		}
	}
}

func assertNoMutation(t *testing.T, response *kubewarden_protocol.ValidationResponse) {
	t.Helper()

	if response.MutatedObject != nil {
		mutatedJSON, _ := json.MarshalIndent(response.MutatedObject, "", "  ")
		t.Errorf("Expected no mutation but got one:\n%s", string(mutatedJSON))
	}
}

func stringPtr(s string) *string {
	return &s
}

func mustMarshalJSON(obj interface{}) []byte {
	data, err := json.Marshal(obj)
	if err != nil {
		panic(err)
	}
	return data
}
