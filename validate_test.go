package main

import (
	"encoding/json"
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

	response, validateErr := validateTest(t, request)
	if validateErr != nil {
		t.Fatalf("Validation failed: %v", validateErr)
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
	if unmarshalErr1 := json.Unmarshal(originalJSON, &original); unmarshalErr1 != nil {
		t.Fatalf("Failed to unmarshal original object: %v", unmarshalErr1)
	}
	if unmarshalErr2 := json.Unmarshal(mutatedJSON, &mutated); unmarshalErr2 != nil {
		t.Fatalf("Failed to unmarshal mutated object: %v", unmarshalErr2)
	}

	// 验证除了注解之外的所有字段都保持不变
	assertObjectsEqual(t, original, mutated, []string{"metadata", "metadata.annotations"})
}

// assertObjectsEqual recursively compares two objects, ignoring specified paths.
func assertObjectsEqual(t *testing.T, original, mutated map[string]interface{}, ignorePaths []string) {
	t.Helper()
	compareObjects(t, "", original, mutated, ignorePaths)
}

// compareObjects compares two objects at a specific path.
func compareObjects(t *testing.T, path string, original, mutated map[string]interface{}, ignorePaths []string) {
	t.Helper()

	// Check for removed or changed fields
	for key, originalValue := range original {
		currentPath := joinPath(path, key)
		if contains(ignorePaths, currentPath) || contains(ignorePaths, key) {
			continue
		}

		mutatedValue, exists := mutated[key]
		if !exists {
			t.Errorf("Field %s was removed", currentPath)
			continue
		}

		compareValues(t, currentPath, originalValue, mutatedValue, ignorePaths)
	}

	// Check for added fields
	for key := range mutated {
		currentPath := joinPath(path, key)
		if _, exists := original[key]; !exists && !contains(ignorePaths, currentPath) && !contains(ignorePaths, key) {
			t.Errorf("Unexpected field added: %s", currentPath)
		}
	}
}

// compareValues compares two values of any type at a specific path.
func compareValues(t *testing.T, path string, original, mutated interface{}, ignorePaths []string) {
	t.Helper()

	switch originalValue := original.(type) {
	case map[string]interface{}:
		mutatedMap, ok := mutated.(map[string]interface{})
		if !ok {
			t.Errorf("Field %s type changed from map to %T", path, mutated)
			return
		}
		compareObjects(t, path, originalValue, mutatedMap, ignorePaths)

	case []interface{}:
		mutatedArray, ok := mutated.([]interface{})
		if !ok {
			t.Errorf("Field %s type changed from array to %T", path, mutated)
			return
		}
		compareArrays(t, path, originalValue, mutatedArray, ignorePaths)

	default:
		if original != mutated {
			t.Errorf("Field %s value changed from %v to %v", path, original, mutated)
		}
	}
}

// compareArrays compares two arrays at a specific path.
func compareArrays(t *testing.T, path string, original, mutated []interface{}, ignorePaths []string) {
	t.Helper()

	if len(original) != len(mutated) {
		t.Errorf("Field %s array length changed from %d to %d", path, len(original), len(mutated))
		return
	}

	for i := range original {
		originalMap, isMap1 := original[i].(map[string]interface{})
		mutatedMap, isMap2 := mutated[i].(map[string]interface{})

		if isMap1 && isMap2 {
			compareObjects(t, joinPath(path, "["+string(rune('0'+i))+"]"), originalMap, mutatedMap, ignorePaths)
		} else if original[i] != mutated[i] {
			t.Errorf("Field %s[%d] value changed from %v to %v", path, i, original[i], mutated[i])
		}
	}
}

// joinPath joins path components with dots.
func joinPath(base, key string) string {
	if base == "" {
		return key
	}
	return base + "." + key
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

	// Verify annotations
	metadata, hasMetadata := mutatedPod["metadata"].(map[string]interface{})
	if !hasMetadata {
		t.Error("Expected metadata in mutated pod")
		return
	}

	annotations, hasAnnotations := metadata["annotations"].(map[string]interface{})
	if !hasAnnotations {
		t.Error("Expected annotations in mutated pod")
		return
	}

	for key, expectedValue := range expectedAnnotations {
		actualValue, hasValue := annotations[key].(string)
		if !hasValue || actualValue != expectedValue {
			t.Errorf("Expected annotation %s to be %s, got %v",
				key, expectedValue, annotations[key])
		}
	}

	// Check for unexpected annotations
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
