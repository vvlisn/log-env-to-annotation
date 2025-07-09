#!/usr/bin/env bats

@test "Pod with no target env variable is mutated with default annotation" {
  run kwctl run \
    -r "test_data/pod-no-env.json" \
    --settings-json '{ "env_key": "vestack_varlog", "annotation_base": "co_elastic_logs_path", "annotation_ext_format": "co_elastic_logs_path_ext_%d" }' \
    "annotated-policy.wasm"

  [ "$status" -eq 0 ]
  [[ "$output" == *'"allowed":true'* ]]
  [[ "$output" == *'"patch"'* ]]
  patch_b64=$(echo "$output" | tail -n 1 | jq -r '.patch')
  patch_decoded=$(echo "$patch_b64" | base64 --decode)
  echo "Decoded Patch (No Env): $patch_decoded"
  echo "$patch_decoded" | jq -e '.[] | select(.op == "add" and .path == "/metadata/annotations" and .value["co.elastic.logs/enabled"] == "true")'
  [ $? -eq 0 ]
}


@test "Pod with single target env variable is mutated with base annotation" {
  run kwctl run \
    -r "test_data/pod-single-env.json" \
    --settings-json '{ "env_key": "vestack_varlog", "annotation_base": "co_elastic_logs_path", "annotation_ext_format": "co_elastic_logs_path_ext_%d" }' \
    "annotated-policy.wasm"

  [ "$status" -eq 0 ]
  [[ "$output" == *'"allowed":true'* ]]
  [[ "$output" == *'"patch"'* ]]
  patch_b64=$(echo "$output" | tail -n 1 | jq -r '.patch')
  patch_decoded=$(echo "$patch_b64" | base64 --decode)
  echo "Decoded Patch (Single Env): $patch_decoded"
  echo "$patch_decoded" | jq -e '.[] | select(.op == "add" and .path == "/metadata/annotations" and .value.co_elastic_logs_path == "/var/log/app.log")'
  [ $? -eq 0 ]
}

@test "Pod with valid additional annotations is mutated with additional annotations" {
  run kwctl run \
    -r "test_data/pod-additional-annotations.json" \
    --settings-json '{ "env_key": "vestack_varlog", "annotation_base": "co_elastic_logs_path", "annotation_ext_format": "co_elastic_logs_path_ext_%d", "additional_annotations": { "example.com/key1": "value1", "example.com/key2": "value2" } }' \
    "annotated-policy.wasm"

  [ "$status" -eq 0 ]
  [[ "$output" == *'"allowed":true'* ]]
  [[ "$output" == *'"patch"'* ]]
  patch_b64=$(echo "$output" | tail -n 1 | jq -r '.patch')
  patch_decoded=$(echo "$patch_b64" | base64 --decode)
  echo "Decoded Patch (Additional Annotations): $patch_decoded"
  echo "$patch_decoded" | jq -e '.[] | select(.op == "add" and .path == "/metadata/annotations" and .value["example.com/key1"] == "value1" and .value["example.com/key2"] == "value2")'
  [ $? -eq 0 ]
}

@test "Pod with invalid additional annotations (empty key) is rejected" {
  run kwctl run \
    -r "test_data/pod-additional-annotations.json" \
    --settings-json '{ "env_key": "vestack_varlog", "annotation_base": "co_elastic_logs_path", "annotation_ext_format": "co_elastic_logs_path_ext_%d", "additional_annotations": { "": "value" } }' \
    "annotated-policy.wasm"

  [ "$status" -ne 0 ]
  [[ "$output" == *'additional_annotations keys cannot be empty'* ]]
  [[ "$output" != *'"allowed":true'* ]]
}


@test "Pod without additional annotations is accepted and not mutated with additional annotations" {
  run kwctl run \
    -r "test_data/pod-additional-annotations.json" \
    --settings-json '{ "env_key": "vestack_varlog", "annotation_base": "co_elastic_logs_path", "annotation_ext_format": "co_elastic_logs_path_ext_%d" }' \
    "annotated-policy.wasm"

  [ "$status" -eq 0 ]
  [[ "$output" == *'"allowed":true'* ]]
  patch_b64=$(echo "$output" | tail -n 1 | jq -r '.patch')
  if [ -n "$patch_b64" ]; then
    patch_decoded=$(echo "$patch_b64" | base64 --decode)
    echo "Decoded Patch: $patch_decoded"
    # 检查patch中是否包含自定义注解键
    if echo "$patch_decoded" | jq -e '.[] | select(.op == "add" and .path == "/metadata/annotations") | .value | (has("example.com/key1") or has("example.com/key2"))' > /dev/null; then
      echo "Error: Found additional annotations in patch"
      return 1
    fi
  fi
  return 0
}

@test "Pod with multiple target env variables is mutated with base and extended annotations" {
  run kwctl run \
    -r "test_data/pod-mulitiple-env.json" \
    --settings-json '{ "env_key": "vestack_varlog", "annotation_base": "co_elastic_logs_path", "annotation_ext_format": "co_elastic_logs_path_ext_%d" }' \
    "annotated-policy.wasm"

  [ "$status" -eq 0 ]
  [[ "$output" == *'"allowed":true'* ]]
  [[ "$output" == *'"patch"'* ]]
  patch_b64=$(echo "$output" | tail -n 1 | jq -r '.patch')
  patch_decoded=$(echo "$patch_b64" | base64 --decode)
  echo "Decoded Patch (Multiple Env): $patch_decoded"
  echo "$patch_decoded" | jq -e '.[] | select(.op == "add" and .path == "/metadata/annotations" and .value.co_elastic_logs_path == "/var/log/apps/common-api-bff/common-api-bff_info.log")'
  [ $? -eq 0 ]
  echo "$patch_decoded" | jq -e '.[] | select(.op == "add" and .path == "/metadata/annotations" and .value.co_elastic_logs_path_ext_1 == "/var/log/apps/service-app_pe/service-app_pe_info.log")'
  [ $? -eq 0 ]
  echo "$patch_decoded" | jq -e '.[] | select(.op == "add" and .path == "/metadata/annotations" and .value.co_elastic_logs_path_ext_2 == "/var/log/apps/common-api-bff/common-api-bff_info.log")'
  [ $? -eq 0 ]
  echo "$patch_decoded" | jq -e '.[] | select(.op == "add" and .path == "/metadata/annotations" and .value.co_elastic_logs_path_ext_3 == "/var/log/apps/app/app_info.log")'
  [ $? -eq 0 ]
  echo "$patch_decoded" | jq -e '.[] | select(.op == "add" and .path == "/metadata/annotations" and .value.co_elastic_logs_path_ext_4 == "/var/log/apps/service-app_pe/service-app_pe_info.log")'
  [ $? -eq 0 ]
}


@test "additional annotations with complex patterns" {
  run kwctl run \
    -r "test_data/pod-single-env.json" \
    --settings-json '{ 
      "env_key": "vestack_varlog",
      "annotation_base": "co_elastic_logs_path",
      "annotation_ext_format": "co_elastic_logs_path_ext_%d",
      "additional_annotations": {
        "co_elastic_logs_multiline_pattern": "^[[:space:]]+(at|\\.{3})[[:space:]]+\\b|^Caused by:",
        "co_elastic_logs_multiline_negate": false,
        "co_elastic_logs_multiline_match": "after"
      }
    }' \
    "annotated-policy.wasm"

  [ "$status" -eq 0 ]
  [[ "$output" == *'"allowed":true'* ]]
  [[ "$output" == *'"patch"'* ]]
  

  patch_b64=$(echo "$output" | tail -n 1 | jq -r '.patch')
  patch_decoded=$(echo "$patch_b64" | base64 --decode)
  echo "Decoded Patch (Complex Patterns): $patch_decoded"
  

  echo "$patch_decoded" | jq -e '
    [
      {"op":"add","path":"/metadata/annotations","value":{
        "co_elastic_logs_multiline_match": "after",
        "co_elastic_logs_multiline_negate": "false",
        "co_elastic_logs_multiline_pattern": "^[[:space:]]+(at|\\.{3})[[:space:]]+\\b|^Caused by:",
        "co_elastic_logs_path": "/var/log/app.log"
      }}
    ]' 
  [ $? -eq 0 ]
}
