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

	var mutatedPod corev1.Pod
	mutatedJSON := mustMarshalJSON(response.MutatedObject)
	if err := json.Unmarshal(mutatedJSON, &mutatedPod); err != nil {
		t.Fatalf("Failed to unmarshal mutated pod: %v", err)
	}

	if mutatedPod.Metadata == nil || mutatedPod.Metadata.Annotations == nil {
		t.Error("Expected annotations but got none")
		return
	}

	for key, expectedValue := range expectedAnnotations {
		if actualValue, exists := mutatedPod.Metadata.Annotations[key]; !exists {
			t.Errorf("Expected annotation %s but it was not found", key)
		} else if actualValue != expectedValue {
			t.Errorf("Expected annotation %s to have value %s but got %s", key, expectedValue, actualValue)
		}
	}

	// Check for unexpected annotations
	for key := range mutatedPod.Metadata.Annotations {
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
