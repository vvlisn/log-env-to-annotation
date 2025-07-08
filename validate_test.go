package main

import (
	"encoding/json"
	"fmt"
	"testing"

	corev1 "github.com/kubewarden/k8s-objects/api/core/v1"
	metav1 "github.com/kubewarden/k8s-objects/apimachinery/pkg/apis/meta/v1"
	kubewarden_protocol "github.com/kubewarden/policy-sdk-go/protocol"
)

// validateTest 是一个辅助函数，用于执行策略验证.
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
			name: "pod with single container and multiple target envs",
			settings: Settings{
				EnvKey:              "LOG_PATH",
				AnnotationBase:      "co_elastic_logs_path",
				AnnotationExtFormat: "co_elastic_logs_path_ext_%d",
			},
			pod: corev1.Pod{
				Spec: &corev1.PodSpec{
					Containers: []*corev1.Container{
						{
							Name: stringPtr("my-container"),
							Env: []*corev1.EnvVar{
								{
									Name:  stringPtr("LOG_PATH"),
									Value: "/var/log/nginx/access.log",
								},
								{
									Name:  stringPtr("LOG_PATH"),
									Value: "/var/log/nginx/error.log",
								},
								{
									Name:  stringPtr("LOG_PATH"),
									Value: "/var/log/nginx/debug.log",
								},
								{
									Name:  stringPtr("LOG_PATH"),
									Value: "/var/log/app/app.log",
								},
								{
									Name:  stringPtr("LOG_PATH"),
									Value: "/var/log/app/error.log",
								},
							},
						},
					},
				},
				Metadata: &metav1.ObjectMeta{},
			},
			expectedAnnotations: map[string]string{
				"co_elastic_logs_path":       "/var/log/nginx/access.log",
				"co_elastic_logs_path_ext_1": "/var/log/nginx/error.log",
				"co_elastic_logs_path_ext_2": "/var/log/nginx/debug.log",
				"co_elastic_logs_path_ext_3": "/var/log/app/app.log",
				"co_elastic_logs_path_ext_4": "/var/log/app/error.log",
			},
			shouldMutate: true,
		},
		{
			name: "pod with multiple containers and target envs",
			settings: Settings{
				EnvKey:              "LOG_PATH",
				AnnotationBase:      "co_elastic_logs_path",
				AnnotationExtFormat: "co_elastic_logs_path_ext_%d",
			},
			pod: corev1.Pod{
				Metadata: &metav1.ObjectMeta{},
				Spec: &corev1.PodSpec{
					Containers: []*corev1.Container{
						{
							Name: stringPtr("container1"),
							Env: []*corev1.EnvVar{
								{Name: stringPtr("LOG_PATH"), Value: "/var/log/app1.log"},
							},
						},
						{
							Name: stringPtr("container2"),
							Env: []*corev1.EnvVar{
								{Name: stringPtr("LOG_PATH"), Value: "/var/log/app2.log"},
							},
						},
					},
				},
			},
			expectedAnnotations: map[string]string{
				"co_elastic_logs_path": "/var/log/app1.log", // 只处理第一个容器
			},
			shouldMutate: true,
		},
		{
			name: "container with nil name",
			settings: Settings{
				EnvKey:              "LOG_PATH",
				AnnotationBase:      "co_elastic_logs_path",
				AnnotationExtFormat: "co_elastic_logs_path_ext_%d",
			},
			pod: corev1.Pod{
				Metadata: &metav1.ObjectMeta{},
				Spec: &corev1.PodSpec{
					Containers: []*corev1.Container{
						{
							Name: nil,
							Env: []*corev1.EnvVar{
								{Name: stringPtr("LOG_PATH"), Value: "/var/log/app.log"},
							},
						},
					},
				},
			},
			expectedAnnotations: map[string]string{},
			shouldMutate:        false,
		},
		{
			name: "pod with no target env",
			settings: Settings{
				EnvKey:              "LOG_PATH",
				AnnotationBase:      "co_elastic_logs_path",
				AnnotationExtFormat: "co_elastic_logs_path_ext_%d",
			},
			pod: corev1.Pod{
				Metadata: &metav1.ObjectMeta{},
				Spec: &corev1.PodSpec{
					Containers: []*corev1.Container{
						{
							Name: stringPtr("my-container"),
							Env: []*corev1.EnvVar{
								{Name: stringPtr("OTHER_ENV"), Value: "some_value"},
							},
						},
					},
				},
			},
			expectedAnnotations: map[string]string{}, // No mutation expected, so empty map
			shouldMutate:        false,
		},
		{
			name: "pod with existing annotations",
			settings: Settings{
				EnvKey:              "LOG_PATH",
				AnnotationBase:      "co_elastic_logs_path",
				AnnotationExtFormat: "co_elastic_logs_path_ext_%d",
			},
			pod: corev1.Pod{
				Metadata: &metav1.ObjectMeta{
					Annotations: map[string]string{
						"existing_annotation": "value",
					},
				},
				Spec: &corev1.PodSpec{
					Containers: []*corev1.Container{
						{
							Name: stringPtr("my-container"),
							Env: []*corev1.EnvVar{
								{Name: stringPtr("LOG_PATH"), Value: "/var/log/app.log"},
							},
						},
					},
				},
			},
			expectedAnnotations: map[string]string{
				"existing_annotation":  "value",
				"co_elastic_logs_path": "/var/log/app.log",
			},
			shouldMutate: true,
		},
		{
			name: "pod with additional annotations",
			settings: Settings{
				EnvKey:              "LOG_PATH",
				AnnotationBase:      "co_elastic_logs_path",
				AnnotationExtFormat: "co_elastic_logs_path_ext_%d",
				AdditionalAnnotations: map[string]interface{}{
					"custom.annotation/key1": "value1",
					"custom.annotation/key2": "value2",
				},
			},
			pod: corev1.Pod{
				Metadata: &metav1.ObjectMeta{},
				Spec: &corev1.PodSpec{
					Containers: []*corev1.Container{
						{
							Name: stringPtr("my-container"),
							Env: []*corev1.EnvVar{
								{Name: stringPtr("LOG_PATH"), Value: "/var/log/app.log"},
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
			name: "pod with no containers",
			settings: Settings{
				EnvKey:              "LOG_PATH",
				AnnotationBase:      "co_elastic_logs_path",
				AnnotationExtFormat: "co_elastic_logs_path_ext_%d",
			},
			pod: corev1.Pod{
				Metadata: &metav1.ObjectMeta{},
				Spec: &corev1.PodSpec{
					Containers: []*corev1.Container{},
				},
			},
			expectedAnnotations: map[string]string{},
			shouldMutate:        false,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			runTest(t, test)
		})
	}
}

func TestNonPodResource(t *testing.T) {
	settings := Settings{
		EnvKey:              "LOG_PATH",
		AnnotationBase:      "co_elastic_logs_path",
		AnnotationExtFormat: "co_elastic_logs_path_ext_%d",
	}

	// Create a non-Pod resource (Service)
	service := map[string]interface{}{
		"apiVersion": "v1",
		"kind":       "Service",
		"metadata": map[string]interface{}{
			"name": "test-service",
		},
		"spec": map[string]interface{}{
			"selector": map[string]interface{}{
				"app": "test",
			},
			"ports": []map[string]interface{}{
				{
					"port":       80,
					"targetPort": 8080,
				},
			},
		},
	}

	serviceJSON := mustMarshalJSON(service)
	settingsJSON := mustMarshalJSON(settings)

	req := kubewarden_protocol.ValidationRequest{
		Request: kubewarden_protocol.KubernetesAdmissionRequest{
			Kind: kubewarden_protocol.GroupVersionKind{
				Kind: "Service",
			},
			Object: serviceJSON,
		},
		Settings: settingsJSON,
	}

	response, err := validateTest(t, req)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	if !response.Accepted {
		t.Errorf("Expected request to be accepted for non-Pod resource")
	}

	if response.MutatedObject != nil {
		t.Errorf("Expected no mutation for non-Pod resource")
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
		t.Errorf("Expected request to be accepted")
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
		t.Errorf("Expected mutation but got none")
		return
	}

	mutatedJSON := mustMarshalJSON(response.MutatedObject)
	var mutatedPod corev1.Pod
	if err := json.Unmarshal(mutatedJSON, &mutatedPod); err != nil {
		t.Fatalf("Failed to unmarshal mutated pod: %v", err)
	}

	if mutatedPod.Metadata == nil || mutatedPod.Metadata.Annotations == nil {
		t.Errorf("Expected annotations but got none")
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
		t.Errorf("Expected no mutation but got one")
	}
}

func stringPtr(s string) *string {
	return &s
}

func mustMarshalJSON(obj interface{}) []byte {
	data, err := json.Marshal(obj)
	if err != nil {
		panic(fmt.Sprintf("Failed to marshal JSON: %v", err))
	}
	return data
}
