[![Stable](https://img.shields.io/badge/status-stable-brightgreen?style=for-the-badge)](https://github.com/kubewarden/community/blob/main/REPOSITORIES.md#stable)

# env-to-annotation-policy

This policy converts specific container environment variables into pod annotations.

## Introduction

This repository contains a Kubewarden policy written in Go. This policy is designed to convert container environment variables into Pod annotations, primarily to facilitate integration with logging systems. By dynamically adding annotations based on environment variables, it allows log collectors to discover and process application logs more effectively.

The policy is configurable via runtime settings.

You can configure the policy using a JSON structure. When using `kwctl run --settings-json`, the settings should be nested under a `signatures` key:

```json
{
  "signatures": [
    {
      "env_key": "MY_LOG_PATH_ENV",
      "annotation_base": "my.company.com/log-path",
      "annotation_ext_format": "my.company.com/log-path-ext-%d",
      "additional_annotations": {
        "example.com/key1": "value1",
        "example.com/key2": "value2"
      }
    }
  ]
}
```

When deploying the policy to a Kubewarden cluster, the settings are typically provided directly without the `signatures` nesting:

```json
{
  "env_key": "MY_LOG_PATH_ENV",
  "annotation_base": "my.company.com/log-path",
  "annotation_ext_format": "my.company.com/log-path-ext-%d",
  "additional_annotations": {
    "example.com/key1": "value1",
    "example.com/key2": "value2"
  }
}
```

The available settings are:
- `env_key` (string, mandatory): The name of the container environment variable whose value will be converted into an annotation.
- `annotation_base` (string, mandatory): The base annotation key name. The value of `env_key` will be assigned to this annotation. If `env_key` contains multiple paths separated by commas, the first path will be assigned to this base annotation.
- `annotation_ext_format` (string, mandatory): The format string for extended annotation keys. If `env_key` contains multiple paths, subsequent paths will be assigned to annotations generated using this format. The string must contain `%d`, which will be replaced by sequence numbers (1, 2, 3...). Example: `my.company.com/log-path-ext-%d`.
- `additional_annotations` (map[string]string, optional): Custom key-value pairs to add as annotations. Both keys and values must be non-empty strings. This parameter is optional and can be omitted if not needed.

## Code organization

The code is organized as follows:
- `settings.go`: Handles policy settings and their validation
- `validate.go`: Contains the main mutation logic that converts environment variables to annotations
- `main.go`: Registers policy entry points with the Kubewarden runtime

## Implementation details

> **DISCLAIMER:** WebAssembly is a constantly evolving area.
> This document describes the status of the Go ecosystem as of 2024.

This policy utilizes several key concepts in its implementation:

1. Environment Variable to Annotation Conversion
   - Iterates through containers in a Pod.
   - Identifies the specified `env_key` environment variable.
   - Processes each occurrence of the environment variable.
   - Adds these values as annotations to the Pod, using `annotation_base` for the first value and `annotation_ext_format` for subsequent values.

2. Custom Annotations
   - Adds any additional annotations specified in the `additional_annotations` parameter.

3. Configuration Management
   - All settings (`env_key`, `annotation_base`, `annotation_ext_format`) are mandatory and validated at policy load time.
   - `additional_annotations` is optional but validated if provided.

4. Technical Considerations
   - Built with TinyGo for WebAssembly compatibility.
   - Uses Kubewarden's TinyGo-compatible Kubernetes types.
   - Implements Kubewarden policy interface:
     - `validate`: Main entry point for Pod mutation.
     - `validate_settings`: Entry point for settings validation.
   - Only processes the first container in each Pod.

See the [Kubewarden Policy SDK](https://github.com/kubewarden/policy-sdk-go) documentation for more details on policy development.

## Testing

The policy includes comprehensive unit tests that verify:

1. Settings validation:
   - Valid settings.
   - Invalid settings (empty `env_key`, `annotation_base`, `annotation_ext_format`, or missing `%d` in `annotation_ext_format`).
   - Validation of `additional_annotations` (empty keys/values).
   - JSON unmarshalling of settings.

2. Pod mutation:
   - Correctly converts a single environment variable to a base annotation.
   - Correctly converts multiple environment variables to base and extended annotations.
   - Adds custom annotations from `additional_annotations`.
   - Handles pods with no target environment variable.
   - Preserves existing annotations.

The unit tests can be run via:

```console
make test
```

The policy also includes end-to-end tests that verify the WebAssembly module behavior using the `kwctl` CLI. These tests validate:

1. Mutation behavior:
   - Correct annotation addition for single and multiple environment variables.
   - Addition of custom annotations.
   - No mutation when the target environment variable is not found.

The e2e tests are implemented in `e2e.bats` and can be run via:

```console
make e2e-tests
```

## Pods Example

Here's how to deploy this policy as a ClusterAdmissionPolicy in Kubernetes:

```yaml
apiVersion: policies.kubewarden.io/v1
kind: ClusterAdmissionPolicy
metadata:
  name: log-env-to-annotation
spec:
  module: registry://ghcr.io/vvlisn/policies/log-env-to-annotation:latest
  rules:
  - apiGroups: [""]
    apiVersions: ["v1"]
    resources: ["pods"]
    operations:
    - CREATE
    - UPDATE
  mutating: true
  settings:
    env_key: varlog
    annotation_base: co_elastic_logs_path
    annotation_ext_format: co_elastic_logs_path_ext_%d
    additional_annotations:
      co_elastic_logs_multiline_pattern: "^[[:space:]]+(at|\.{3})[[:space:]]+\b|^Caused by:"
      co_elastic_logs_multiline_negate: false
      co_elastic_logs_multiline_match: after
```

## Automation

This project has the following [GitHub Actions](https://docs.github.com/en/actions):

- `e2e-tests`: this action builds the WebAssembly policy,
installs the `bats` utility and then runs the end-to-end test.
- `unit-tests`: this action runs the Go unit tests.
- `release`: this action builds the WebAssembly policy and pushes it to a user defined OCI registry
([ghcr](https://ghcr.io) is a good candidate).
