# Guardian Report: run 73933422

181 components, 361 edges, 12 unique vulnerabilities, 6 non-CVE findings.

## Top findings

| Score | Conf | SSVC | Finding | Component | Reachability | Resolution |
|---|---|---|---|---|---|---|
| 31.4 | Medium | Track | CVE-2026-111181 | body-parser@2.3.0 | used_transitively | plan proposed |
| 28.0 | Medium | Track | TYPOSQUAT_SUSPECT | cors@2.8.6 | used_transitively | plan proposed |
| 26.0 | Medium | Track | CVE-2026-126343 | node-server@2.1.5 | used_transitively | plan proposed |
| 25.3 | Medium | Track | CVE-2026-126357 | hono@4.13.13 | used_transitively | plan proposed |
| 25.2 | Medium | Track | CVE-2026-126356 | hono@4.13.13 | used_transitively | plan proposed |
| 24.9 | Medium | Track | CVE-2026-126210 | node-server@2.1.5 | used_transitively | plan proposed |
| 24.9 | Medium | Track | CVE-2026-110306 | fast-uri@3.1.8 | used_transitively | plan proposed |
| 24.8 | Medium | Track | CVE-2026-126358 | hono@4.13.13 | used_transitively | plan proposed |
| 22.0 | Medium | Track | UNPINNED_BASE_IMAGE | Dockerfile | n/a | plan proposed |
| 22.0 | Medium | Track | UNPINNED_BASE_IMAGE | Dockerfile | n/a | plan proposed |
| 21.3 | Medium | Track | CVE-2026-126355 | hono@4.13.13 | used_transitively | plan proposed |
| 21.3 | Medium | Track | CVE-2026-110180 | fast-uri@3.1.8 | used_transitively | plan proposed |
| 20.0 | Medium | Track | INSTALL_SCRIPT | esbuild@0.28.2 | not_imported | open |
| 20.0 | Medium | Track | INSTALL_SCRIPT | fsevents@2.3.3 | not_imported | open |
| 19.0 | Medium | Track | CVE-2026-110725 | fast-uri@3.1.8 | used_transitively | plan proposed |
| 18.8 | Medium | Track | CVE-2026-110095 | fast-uri@3.1.8 | used_transitively | plan proposed |
| 17.4 | Medium | Track | CVE-2026-126359 | hono@4.13.13 | used_transitively | plan proposed |
| 12.0 | Medium | Track | DS-0026 | file:Dockerfile | n/a | plan proposed |

## What changed

- no baseline supplied, or no changes found

## Dependency graph

```mermaid
flowchart LR
  app(["application"])
  pkg_npm__40aws_sdk_client_bedrock_runtime_3_1152_0["@aws-sdk/client-bedrock-runtime@3.1152.0"]
  pkg_npm__40aws_sdk_core_3_978_3["@aws-sdk/core@3.978.3"]
  pkg_npm__40aws_sdk_credential_provider_env_3_972_74["@aws-sdk/credential-provider-env@3.972.74"]
  pkg_npm__40aws_sdk_credential_provider_http_3_972_76["@aws-sdk/credential-provider-http@3.972.76"]
  pkg_npm__40aws_sdk_credential_provider_ini_3_973_19["@aws-sdk/credential-provider-ini@3.973.19"]
  pkg_npm__40aws_sdk_credential_provider_login_3_972_81["@aws-sdk/credential-provider-login@3.972.81"]
  pkg_npm__40aws_sdk_credential_provider_node_3_972_86["@aws-sdk/credential-provider-node@3.972.86"]
  pkg_npm__40aws_sdk_credential_provider_process_3_972_74["@aws-sdk/credential-provider-process@3.972.74"]
  pkg_npm__40aws_sdk_credential_provider_sso_3_973_18["@aws-sdk/credential-provider-sso@3.973.18"]
  pkg_npm__40aws_sdk_credential_provider_web_identity_3_972_80["@aws-sdk/credential-provider-web-identity@3.972.80"]
  pkg_npm__40aws_sdk_eventstream_handler_node_3_972_36["@aws-sdk/eventstream-handler-node@3.972.36"]
  pkg_npm__40aws_sdk_middleware_eventstream_3_972_31["@aws-sdk/middleware-eventstream@3.972.31"]
  pkg_npm__40aws_sdk_middleware_websocket_3_972_56["@aws-sdk/middleware-websocket@3.972.56"]
  pkg_npm__40aws_sdk_nested_clients_3_997_48["@aws-sdk/nested-clients@3.997.48"]
  pkg_npm__40aws_sdk_signature_v4_multi_region_3_996_48["@aws-sdk/signature-v4-multi-region@3.996.48"]
  pkg_npm__40aws_sdk_token_providers_3_1150_0["@aws-sdk/token-providers@3.1150.0"]
  pkg_npm__40aws_sdk_token_providers_3_1152_0["@aws-sdk/token-providers@3.1152.0"]
  pkg_npm__40aws_sdk_types_3_974_6["@aws-sdk/types@3.974.6"]
  pkg_npm__40aws_sdk_xml_builder_3_972_41["@aws-sdk/xml-builder@3.972.41"]
  pkg_npm__40aws_lambda_invoke_store_0_3_0["@aws/lambda-invoke-store@0.3.0"]
  pkg_npm__40esbuild_aix_ppc64_0_28_2["@esbuild/aix-ppc64@0.28.2"]
  pkg_npm__40esbuild_android_arm64_0_28_2["@esbuild/android-arm64@0.28.2"]
  pkg_npm__40esbuild_android_arm_0_28_2["@esbuild/android-arm@0.28.2"]
  pkg_npm__40esbuild_android_x64_0_28_2["@esbuild/android-x64@0.28.2"]
  pkg_npm__40esbuild_darwin_arm64_0_28_2["@esbuild/darwin-arm64@0.28.2"]
  pkg_npm__40esbuild_darwin_x64_0_28_2["@esbuild/darwin-x64@0.28.2"]
  pkg_npm__40esbuild_freebsd_arm64_0_28_2["@esbuild/freebsd-arm64@0.28.2"]
  pkg_npm__40esbuild_freebsd_x64_0_28_2["@esbuild/freebsd-x64@0.28.2"]
  pkg_npm__40esbuild_linux_arm64_0_28_2["@esbuild/linux-arm64@0.28.2"]
  pkg_npm__40esbuild_linux_arm_0_28_2["@esbuild/linux-arm@0.28.2"]
  pkg_npm__40esbuild_linux_ia32_0_28_2["@esbuild/linux-ia32@0.28.2"]
  pkg_npm__40esbuild_linux_loong64_0_28_2["@esbuild/linux-loong64@0.28.2"]
  pkg_npm__40esbuild_linux_mips64el_0_28_2["@esbuild/linux-mips64el@0.28.2"]
  pkg_npm__40esbuild_linux_ppc64_0_28_2["@esbuild/linux-ppc64@0.28.2"]
  pkg_npm__40esbuild_linux_riscv64_0_28_2["@esbuild/linux-riscv64@0.28.2"]
  pkg_npm__40esbuild_linux_s390x_0_28_2["@esbuild/linux-s390x@0.28.2"]
  pkg_npm__40esbuild_linux_x64_0_28_2["@esbuild/linux-x64@0.28.2"]
  pkg_npm__40esbuild_netbsd_arm64_0_28_2["@esbuild/netbsd-arm64@0.28.2"]
  pkg_npm__40esbuild_netbsd_x64_0_28_2["@esbuild/netbsd-x64@0.28.2"]
  pkg_npm__40esbuild_openbsd_arm64_0_28_2["@esbuild/openbsd-arm64@0.28.2"]
  pkg_npm__40esbuild_openbsd_x64_0_28_2["@esbuild/openbsd-x64@0.28.2"]
  pkg_npm__40esbuild_openharmony_arm64_0_28_2["@esbuild/openharmony-arm64@0.28.2"]
  pkg_npm__40esbuild_sunos_x64_0_28_2["@esbuild/sunos-x64@0.28.2"]
  pkg_npm__40esbuild_win32_arm64_0_28_2["@esbuild/win32-arm64@0.28.2"]
  pkg_npm__40esbuild_win32_ia32_0_28_2["@esbuild/win32-ia32@0.28.2"]
  pkg_npm__40esbuild_win32_x64_0_28_2["@esbuild/win32-x64@0.28.2"]
  pkg_npm__40hono_node_server_2_1_5["@hono/node-server@2.1.5<br/>2 vulns"]
  pkg_npm__40modelcontextprotocol_sdk_1_32_1["@modelcontextprotocol/sdk@1.32.1"]
  pkg_npm__40smithy_core_3_36_0["@smithy/core@3.36.0"]
  pkg_npm__40smithy_credential_provider_imds_4_5_2["@smithy/credential-provider-imds@4.5.2"]
  pkg_npm__40smithy_fetch_http_handler_5_8_0["@smithy/fetch-http-handler@5.8.0"]
  pkg_npm__40smithy_node_http_handler_4_12_1["@smithy/node-http-handler@4.12.1"]
  pkg_npm__40smithy_signature_v4_5_7_4["@smithy/signature-v4@5.7.4"]
  pkg_npm__40smithy_types_4_19_0["@smithy/types@4.19.0"]
  pkg_npm__40types_body_parser_1_19_6["@types/body-parser@1.19.6"]
  pkg_npm__40types_connect_3_4_38["@types/connect@3.4.38"]
  pkg_npm__40types_express_serve_static_core_5_1_3["@types/express-serve-static-core@5.1.3"]
  pkg_npm__40types_express_5_0_6["@types/express@5.0.6"]
  pkg_npm__40types_http_errors_2_0_5["@types/http-errors@2.0.5"]
  pkg_npm__40types_node_26_6_5["@types/node@26.6.5"]
  pkg_npm__40types_qs_6_15_1["@types/qs@6.15.1"]
  pkg_npm__40types_range_parser_1_2_7["@types/range-parser@1.2.7"]
  pkg_npm__40types_send_1_2_1["@types/send@1.2.1"]
  pkg_npm__40types_serve_static_2_2_0["@types/serve-static@2.2.0"]
  pkg_npm__40typescript_typescript_aix_ppc64_7_0_2["@typescript/typescript-aix-ppc64@7.0.2"]
  pkg_npm__40typescript_typescript_darwin_arm64_7_0_2["@typescript/typescript-darwin-arm64@7.0.2"]
  pkg_npm__40typescript_typescript_darwin_x64_7_0_2["@typescript/typescript-darwin-x64@7.0.2"]
  pkg_npm__40typescript_typescript_freebsd_arm64_7_0_2["@typescript/typescript-freebsd-arm64@7.0.2"]
  pkg_npm__40typescript_typescript_freebsd_x64_7_0_2["@typescript/typescript-freebsd-x64@7.0.2"]
  pkg_npm__40typescript_typescript_linux_arm64_7_0_2["@typescript/typescript-linux-arm64@7.0.2"]
  pkg_npm__40typescript_typescript_linux_arm_7_0_2["@typescript/typescript-linux-arm@7.0.2"]
  pkg_npm__40typescript_typescript_linux_loong64_7_0_2["@typescript/typescript-linux-loong64@7.0.2"]
  pkg_npm__40typescript_typescript_linux_mips64el_7_0_2["@typescript/typescript-linux-mips64el@7.0.2"]
  pkg_npm__40typescript_typescript_linux_ppc64_7_0_2["@typescript/typescript-linux-ppc64@7.0.2"]
  pkg_npm__40typescript_typescript_linux_riscv64_7_0_2["@typescript/typescript-linux-riscv64@7.0.2"]
  pkg_npm__40typescript_typescript_linux_s390x_7_0_2["@typescript/typescript-linux-s390x@7.0.2"]
  pkg_npm__40typescript_typescript_linux_x64_7_0_2["@typescript/typescript-linux-x64@7.0.2"]
  pkg_npm__40typescript_typescript_netbsd_arm64_7_0_2["@typescript/typescript-netbsd-arm64@7.0.2"]
  pkg_npm__40typescript_typescript_netbsd_x64_7_0_2["@typescript/typescript-netbsd-x64@7.0.2"]
  pkg_npm__40typescript_typescript_openbsd_arm64_7_0_2["@typescript/typescript-openbsd-arm64@7.0.2"]
  pkg_npm__40typescript_typescript_openbsd_x64_7_0_2["@typescript/typescript-openbsd-x64@7.0.2"]
  pkg_npm__40typescript_typescript_sunos_x64_7_0_2["@typescript/typescript-sunos-x64@7.0.2"]
  pkg_npm__40typescript_typescript_win32_arm64_7_0_2["@typescript/typescript-win32-arm64@7.0.2"]
  pkg_npm__40typescript_typescript_win32_x64_7_0_2["@typescript/typescript-win32-x64@7.0.2"]
  pkg_npm_accepts_2_0_0["accepts@2.0.0"]
  pkg_npm_ajv_formats_3_0_1["ajv-formats@3.0.1"]
  pkg_npm_ajv_8_20_0["ajv@8.20.0"]
  pkg_npm_body_parser_2_3_0["body-parser@2.3.0<br/>1 vulns"]
  pkg_npm_bowser_2_14_1["bowser@2.14.1"]
  pkg_npm_bytes_3_1_2["bytes@3.1.2"]
  pkg_npm_call_bind_apply_helpers_1_0_2["call-bind-apply-helpers@1.0.2"]
  pkg_npm_call_bound_1_0_4["call-bound@1.0.4"]
  pkg_npm_content_disposition_2_0_1["content-disposition@2.0.1"]
  pkg_npm_content_type_1_0_5["content-type@1.0.5"]
  pkg_npm_content_type_2_1_0["content-type@2.1.0"]
  pkg_npm_cookie_signature_1_2_2["cookie-signature@1.2.2"]
  pkg_npm_cookie_0_7_2["cookie@0.7.2"]
  pkg_npm_cors_2_8_6["cors@2.8.6"]
  pkg_npm_cross_spawn_7_0_6["cross-spawn@7.0.6"]
  pkg_npm_debug_4_4_3["debug@4.4.3"]
  pkg_npm_depd_2_0_0["depd@2.0.0"]
  pkg_npm_dunder_proto_1_0_1["dunder-proto@1.0.1"]
  pkg_npm_ee_first_1_1_1["ee-first@1.1.1"]
  pkg_npm_encodeurl_2_0_0["encodeurl@2.0.0"]
  pkg_npm_es_define_property_1_0_1["es-define-property@1.0.1"]
  pkg_npm_es_errors_1_3_0["es-errors@1.3.0"]
  pkg_npm_es_object_atoms_1_1_2["es-object-atoms@1.1.2"]
  pkg_npm_esbuild_0_28_2["esbuild@0.28.2"]
  pkg_npm_escape_html_1_0_3["escape-html@1.0.3"]
  pkg_npm_etag_1_8_1["etag@1.8.1"]
  pkg_npm_eventsource_parser_3_1_1["eventsource-parser@3.1.1"]
  pkg_npm_eventsource_3_0_7["eventsource@3.0.7"]
  pkg_npm_express_rate_limit_8_7_1["express-rate-limit@8.7.1"]
  pkg_npm_express_5_3_0["express@5.3.0"]
  pkg_npm_fast_deep_equal_3_1_3["fast-deep-equal@3.1.3"]
  pkg_npm_fast_uri_3_1_8["fast-uri@3.1.8<br/>4 vulns"]
  pkg_npm_finalhandler_2_1_1["finalhandler@2.1.1"]
  pkg_npm_forwarded_0_2_0["forwarded@0.2.0"]
  pkg_npm_fresh_2_0_0["fresh@2.0.0"]
  pkg_npm_fsevents_2_3_3["fsevents@2.3.3"]
  pkg_npm_function_bind_1_1_2["function-bind@1.1.2"]
  pkg_npm_get_intrinsic_1_3_0["get-intrinsic@1.3.0"]
  pkg_npm_get_proto_1_0_1["get-proto@1.0.1"]
  pkg_npm_gopd_1_2_0["gopd@1.2.0"]
  pkg_npm_has_symbols_1_1_0["has-symbols@1.1.0"]
  pkg_npm_hasown_2_0_4["hasown@2.0.4"]
  pkg_npm_hono_4_13_13["hono@4.13.13<br/>5 vulns"]
  pkg_npm_http_errors_2_0_1["http-errors@2.0.1"]
  pkg_npm_iconv_lite_0_7_3["iconv-lite@0.7.3"]
  pkg_npm_inherits_2_0_4["inherits@2.0.4"]
  pkg_npm_ip_address_10_7_4["ip-address@10.7.4"]
  pkg_npm_ipaddr_js_1_9_1["ipaddr.js@1.9.1"]
  pkg_npm_is_promise_4_0_0["is-promise@4.0.0"]
  pkg_npm_isexe_2_0_0["isexe@2.0.0"]
  pkg_npm_jose_6_2_12["jose@6.2.12"]
  pkg_npm_json_schema_traverse_1_0_0["json-schema-traverse@1.0.0"]
  pkg_npm_json_schema_typed_8_0_2["json-schema-typed@8.0.2"]
  pkg_npm_math_intrinsics_1_1_0["math-intrinsics@1.1.0"]
  pkg_npm_media_typer_1_1_1["media-typer@1.1.1"]
  pkg_npm_merge_descriptors_2_0_0["merge-descriptors@2.0.0"]
  pkg_npm_mime_db_1_54_0["mime-db@1.54.0"]
  pkg_npm_mime_types_3_0_2["mime-types@3.0.2"]
  pkg_npm_ms_2_1_3["ms@2.1.3"]
  pkg_npm_negotiator_1_1_0["negotiator@1.1.0"]
  pkg_npm_object_assign_4_1_1["object-assign@4.1.1"]
  pkg_npm_object_inspect_1_13_4["object-inspect@1.13.4"]
  pkg_npm_on_finished_2_4_1["on-finished@2.4.1"]
  pkg_npm_once_1_4_0["once@1.4.0"]
  pkg_npm_parseurl_1_3_3["parseurl@1.3.3"]
  pkg_npm_path_key_3_1_1["path-key@3.1.1"]
  pkg_npm_path_to_regexp_8_4_2["path-to-regexp@8.4.2"]
  pkg_npm_pkce_challenge_5_0_1["pkce-challenge@5.0.1"]
  pkg_npm_proxy_addr_2_0_8["proxy-addr@2.0.8"]
  pkg_npm_qs_6_16_1["qs@6.16.1"]
  pkg_npm_range_parser_1_3_0["range-parser@1.3.0"]
  pkg_npm_raw_body_3_0_2["raw-body@3.0.2"]
  pkg_npm_require_from_string_2_0_2["require-from-string@2.0.2"]
  pkg_npm_router_2_2_0["router@2.2.0"]
  pkg_npm_safer_buffer_2_1_2["safer-buffer@2.1.2"]
  pkg_npm_send_1_2_1["send@1.2.1"]
  pkg_npm_serve_static_2_2_1["serve-static@2.2.1"]
  pkg_npm_setprototypeof_1_2_0["setprototypeof@1.2.0"]
  pkg_npm_shebang_command_2_0_0["shebang-command@2.0.0"]
  pkg_npm_shebang_regex_3_0_0["shebang-regex@3.0.0"]
  pkg_npm_side_channel_list_1_0_1["side-channel-list@1.0.1"]
  pkg_npm_side_channel_map_1_0_1["side-channel-map@1.0.1"]
  pkg_npm_side_channel_weakmap_1_0_2["side-channel-weakmap@1.0.2"]
  pkg_npm_side_channel_1_1_1["side-channel@1.1.1"]
  pkg_npm_statuses_2_0_2["statuses@2.0.2"]
  pkg_npm_toidentifier_1_0_1["toidentifier@1.0.1"]
  pkg_npm_tslib_2_8_1["tslib@2.8.1"]
  pkg_npm_tsx_4_23_15["tsx@4.23.15"]
  pkg_npm_type_is_2_1_0["type-is@2.1.0"]
  pkg_npm_typescript_7_0_2["typescript@7.0.2"]
  pkg_npm_undici_types_8_9_0["undici-types@8.9.0"]
  pkg_npm_unpipe_1_0_0["unpipe@1.0.0"]
  pkg_npm_vary_1_1_2["vary@1.1.2"]
  pkg_npm_which_2_0_2["which@2.0.2"]
  pkg_npm_wrappy_1_0_2["wrappy@1.0.2"]
  pkg_npm_zod_to_json_schema_3_25_2["zod-to-json-schema@3.25.2"]
  pkg_npm_zod_4_6_7["zod@4.6.7"]
  app --> pkg_npm__40aws_sdk_client_bedrock_runtime_3_1152_0
  app --> pkg_npm__40modelcontextprotocol_sdk_1_32_1
  app --> pkg_npm__40types_express_5_0_6
  app --> pkg_npm__40types_node_26_6_5
  app --> pkg_npm_express_5_3_0
  app --> pkg_npm_tsx_4_23_15
  app --> pkg_npm_typescript_7_0_2
  app --> pkg_npm_zod_4_6_7
  pkg_npm__40smithy_types_4_19_0 --> pkg_npm_tslib_2_8_1
  pkg_npm__40aws_sdk_types_3_974_6 --> pkg_npm__40smithy_types_4_19_0
  pkg_npm__40aws_sdk_types_3_974_6 --> pkg_npm_tslib_2_8_1
  pkg_npm__40aws_sdk_xml_builder_3_972_41 --> pkg_npm__40smithy_types_4_19_0
  pkg_npm__40aws_sdk_xml_builder_3_972_41 --> pkg_npm_tslib_2_8_1
  pkg_npm__40smithy_core_3_36_0 --> pkg_npm__40smithy_types_4_19_0
  pkg_npm__40smithy_core_3_36_0 --> pkg_npm_tslib_2_8_1
  pkg_npm__40smithy_signature_v4_5_7_4 --> pkg_npm__40smithy_core_3_36_0
  pkg_npm__40smithy_signature_v4_5_7_4 --> pkg_npm__40smithy_types_4_19_0
  pkg_npm__40smithy_signature_v4_5_7_4 --> pkg_npm_tslib_2_8_1
  pkg_npm__40aws_sdk_core_3_978_3 --> pkg_npm__40aws_sdk_types_3_974_6
  pkg_npm__40aws_sdk_core_3_978_3 --> pkg_npm__40aws_sdk_xml_builder_3_972_41
  pkg_npm__40aws_sdk_core_3_978_3 --> pkg_npm__40aws_lambda_invoke_store_0_3_0
  pkg_npm__40aws_sdk_core_3_978_3 --> pkg_npm__40smithy_core_3_36_0
  pkg_npm__40aws_sdk_core_3_978_3 --> pkg_npm__40smithy_signature_v4_5_7_4
  pkg_npm__40aws_sdk_core_3_978_3 --> pkg_npm__40smithy_types_4_19_0
  pkg_npm__40aws_sdk_core_3_978_3 --> pkg_npm_bowser_2_14_1
  pkg_npm__40aws_sdk_core_3_978_3 --> pkg_npm_tslib_2_8_1
  pkg_npm__40aws_sdk_credential_provider_env_3_972_74 --> pkg_npm__40aws_sdk_core_3_978_3
  pkg_npm__40aws_sdk_credential_provider_env_3_972_74 --> pkg_npm__40aws_sdk_types_3_974_6
  pkg_npm__40aws_sdk_credential_provider_env_3_972_74 --> pkg_npm__40smithy_core_3_36_0
  pkg_npm__40aws_sdk_credential_provider_env_3_972_74 --> pkg_npm__40smithy_types_4_19_0
  pkg_npm__40aws_sdk_credential_provider_env_3_972_74 --> pkg_npm_tslib_2_8_1
  pkg_npm__40smithy_fetch_http_handler_5_8_0 --> pkg_npm__40smithy_core_3_36_0
  pkg_npm__40smithy_fetch_http_handler_5_8_0 --> pkg_npm__40smithy_types_4_19_0
  pkg_npm__40smithy_fetch_http_handler_5_8_0 --> pkg_npm_tslib_2_8_1
  pkg_npm__40smithy_node_http_handler_4_12_1 --> pkg_npm__40smithy_core_3_36_0
  pkg_npm__40smithy_node_http_handler_4_12_1 --> pkg_npm__40smithy_types_4_19_0
  pkg_npm__40smithy_node_http_handler_4_12_1 --> pkg_npm_tslib_2_8_1
  pkg_npm__40aws_sdk_credential_provider_http_3_972_76 --> pkg_npm__40aws_sdk_core_3_978_3
  pkg_npm__40aws_sdk_credential_provider_http_3_972_76 --> pkg_npm__40aws_sdk_types_3_974_6
  pkg_npm__40aws_sdk_credential_provider_http_3_972_76 --> pkg_npm__40smithy_core_3_36_0
  pkg_npm__40aws_sdk_credential_provider_http_3_972_76 --> pkg_npm__40smithy_fetch_http_handler_5_8_0
  pkg_npm__40aws_sdk_credential_provider_http_3_972_76 --> pkg_npm__40smithy_node_http_handler_4_12_1
  pkg_npm__40aws_sdk_credential_provider_http_3_972_76 --> pkg_npm__40smithy_types_4_19_0
  pkg_npm__40aws_sdk_credential_provider_http_3_972_76 --> pkg_npm_tslib_2_8_1
  pkg_npm__40aws_sdk_signature_v4_multi_region_3_996_48 --> pkg_npm__40aws_sdk_types_3_974_6
  pkg_npm__40aws_sdk_signature_v4_multi_region_3_996_48 --> pkg_npm__40smithy_signature_v4_5_7_4
  pkg_npm__40aws_sdk_signature_v4_multi_region_3_996_48 --> pkg_npm__40smithy_types_4_19_0
  pkg_npm__40aws_sdk_signature_v4_multi_region_3_996_48 --> pkg_npm_tslib_2_8_1
  pkg_npm__40aws_sdk_nested_clients_3_997_48 --> pkg_npm__40aws_sdk_core_3_978_3
  pkg_npm__40aws_sdk_nested_clients_3_997_48 --> pkg_npm__40aws_sdk_signature_v4_multi_region_3_996_48
  pkg_npm__40aws_sdk_nested_clients_3_997_48 --> pkg_npm__40aws_sdk_types_3_974_6
  pkg_npm__40aws_sdk_nested_clients_3_997_48 --> pkg_npm__40smithy_core_3_36_0
  pkg_npm__40aws_sdk_nested_clients_3_997_48 --> pkg_npm__40smithy_fetch_http_handler_5_8_0
  pkg_npm__40aws_sdk_nested_clients_3_997_48 --> pkg_npm__40smithy_node_http_handler_4_12_1
  pkg_npm__40aws_sdk_nested_clients_3_997_48 --> pkg_npm__40smithy_types_4_19_0
  pkg_npm__40aws_sdk_nested_clients_3_997_48 --> pkg_npm_tslib_2_8_1
  pkg_npm__40aws_sdk_credential_provider_login_3_972_81 --> pkg_npm__40aws_sdk_core_3_978_3
  pkg_npm__40aws_sdk_credential_provider_login_3_972_81 --> pkg_npm__40aws_sdk_nested_clients_3_997_48
  pkg_npm__40aws_sdk_credential_provider_login_3_972_81 --> pkg_npm__40aws_sdk_types_3_974_6
  pkg_npm__40aws_sdk_credential_provider_login_3_972_81 --> pkg_npm__40smithy_core_3_36_0
  pkg_npm__40aws_sdk_credential_provider_login_3_972_81 --> pkg_npm__40smithy_types_4_19_0
  pkg_npm__40aws_sdk_credential_provider_login_3_972_81 --> pkg_npm_tslib_2_8_1
  pkg_npm__40aws_sdk_credential_provider_process_3_972_74 --> pkg_npm__40aws_sdk_core_3_978_3
  pkg_npm__40aws_sdk_credential_provider_process_3_972_74 --> pkg_npm__40aws_sdk_types_3_974_6
  pkg_npm__40aws_sdk_credential_provider_process_3_972_74 --> pkg_npm__40smithy_core_3_36_0
  pkg_npm__40aws_sdk_credential_provider_process_3_972_74 --> pkg_npm__40smithy_types_4_19_0
  pkg_npm__40aws_sdk_credential_provider_process_3_972_74 --> pkg_npm_tslib_2_8_1
  pkg_npm__40aws_sdk_token_providers_3_1150_0 --> pkg_npm__40aws_sdk_core_3_978_3
  pkg_npm__40aws_sdk_token_providers_3_1150_0 --> pkg_npm__40aws_sdk_nested_clients_3_997_48
  pkg_npm__40aws_sdk_token_providers_3_1150_0 --> pkg_npm__40aws_sdk_types_3_974_6
  pkg_npm__40aws_sdk_token_providers_3_1150_0 --> pkg_npm__40smithy_core_3_36_0
  pkg_npm__40aws_sdk_token_providers_3_1150_0 --> pkg_npm__40smithy_types_4_19_0
  pkg_npm__40aws_sdk_token_providers_3_1150_0 --> pkg_npm_tslib_2_8_1
  pkg_npm__40aws_sdk_credential_provider_sso_3_973_18 --> pkg_npm__40aws_sdk_core_3_978_3
  pkg_npm__40aws_sdk_credential_provider_sso_3_973_18 --> pkg_npm__40aws_sdk_nested_clients_3_997_48
  pkg_npm__40aws_sdk_credential_provider_sso_3_973_18 --> pkg_npm__40aws_sdk_token_providers_3_1150_0
  pkg_npm__40aws_sdk_credential_provider_sso_3_973_18 --> pkg_npm__40aws_sdk_types_3_974_6
  pkg_npm__40aws_sdk_credential_provider_sso_3_973_18 --> pkg_npm__40smithy_core_3_36_0
  pkg_npm__40aws_sdk_credential_provider_sso_3_973_18 --> pkg_npm__40smithy_types_4_19_0
  pkg_npm__40aws_sdk_credential_provider_sso_3_973_18 --> pkg_npm_tslib_2_8_1
  pkg_npm__40aws_sdk_credential_provider_web_identity_3_972_80 --> pkg_npm__40aws_sdk_core_3_978_3
  pkg_npm__40aws_sdk_credential_provider_web_identity_3_972_80 --> pkg_npm__40aws_sdk_nested_clients_3_997_48
  pkg_npm__40aws_sdk_credential_provider_web_identity_3_972_80 --> pkg_npm__40aws_sdk_types_3_974_6
  pkg_npm__40aws_sdk_credential_provider_web_identity_3_972_80 --> pkg_npm__40smithy_core_3_36_0
  pkg_npm__40aws_sdk_credential_provider_web_identity_3_972_80 --> pkg_npm__40smithy_types_4_19_0
  pkg_npm__40aws_sdk_credential_provider_web_identity_3_972_80 --> pkg_npm_tslib_2_8_1
  pkg_npm__40smithy_credential_provider_imds_4_5_2 --> pkg_npm__40smithy_core_3_36_0
  pkg_npm__40smithy_credential_provider_imds_4_5_2 --> pkg_npm__40smithy_types_4_19_0
  pkg_npm__40smithy_credential_provider_imds_4_5_2 --> pkg_npm_tslib_2_8_1
  pkg_npm__40aws_sdk_credential_provider_ini_3_973_19 --> pkg_npm__40aws_sdk_core_3_978_3
  pkg_npm__40aws_sdk_credential_provider_ini_3_973_19 --> pkg_npm__40aws_sdk_credential_provider_env_3_972_74
  pkg_npm__40aws_sdk_credential_provider_ini_3_973_19 --> pkg_npm__40aws_sdk_credential_provider_http_3_972_76
  pkg_npm__40aws_sdk_credential_provider_ini_3_973_19 --> pkg_npm__40aws_sdk_credential_provider_login_3_972_81
  pkg_npm__40aws_sdk_credential_provider_ini_3_973_19 --> pkg_npm__40aws_sdk_credential_provider_process_3_972_74
  pkg_npm__40aws_sdk_credential_provider_ini_3_973_19 --> pkg_npm__40aws_sdk_credential_provider_sso_3_973_18
  pkg_npm__40aws_sdk_credential_provider_ini_3_973_19 --> pkg_npm__40aws_sdk_credential_provider_web_identity_3_972_80
  pkg_npm__40aws_sdk_credential_provider_ini_3_973_19 --> pkg_npm__40aws_sdk_nested_clients_3_997_48
  pkg_npm__40aws_sdk_credential_provider_ini_3_973_19 --> pkg_npm__40aws_sdk_types_3_974_6
  pkg_npm__40aws_sdk_credential_provider_ini_3_973_19 --> pkg_npm__40smithy_core_3_36_0
  pkg_npm__40aws_sdk_credential_provider_ini_3_973_19 --> pkg_npm__40smithy_credential_provider_imds_4_5_2
  pkg_npm__40aws_sdk_credential_provider_ini_3_973_19 --> pkg_npm__40smithy_types_4_19_0
  pkg_npm__40aws_sdk_credential_provider_ini_3_973_19 --> pkg_npm_tslib_2_8_1
  pkg_npm__40aws_sdk_credential_provider_node_3_972_86 --> pkg_npm__40aws_sdk_credential_provider_env_3_972_74
  pkg_npm__40aws_sdk_credential_provider_node_3_972_86 --> pkg_npm__40aws_sdk_credential_provider_http_3_972_76
  pkg_npm__40aws_sdk_credential_provider_node_3_972_86 --> pkg_npm__40aws_sdk_credential_provider_ini_3_973_19
  pkg_npm__40aws_sdk_credential_provider_node_3_972_86 --> pkg_npm__40aws_sdk_credential_provider_process_3_972_74
  pkg_npm__40aws_sdk_credential_provider_node_3_972_86 --> pkg_npm__40aws_sdk_credential_provider_sso_3_973_18
  pkg_npm__40aws_sdk_credential_provider_node_3_972_86 --> pkg_npm__40aws_sdk_credential_provider_web_identity_3_972_80
  pkg_npm__40aws_sdk_credential_provider_node_3_972_86 --> pkg_npm__40aws_sdk_types_3_974_6
  pkg_npm__40aws_sdk_credential_provider_node_3_972_86 --> pkg_npm__40smithy_core_3_36_0
  pkg_npm__40aws_sdk_credential_provider_node_3_972_86 --> pkg_npm__40smithy_credential_provider_imds_4_5_2
  pkg_npm__40aws_sdk_credential_provider_node_3_972_86 --> pkg_npm__40smithy_types_4_19_0
  pkg_npm__40aws_sdk_credential_provider_node_3_972_86 --> pkg_npm_tslib_2_8_1
  pkg_npm__40aws_sdk_eventstream_handler_node_3_972_36 --> pkg_npm__40aws_sdk_types_3_974_6
  pkg_npm__40aws_sdk_eventstream_handler_node_3_972_36 --> pkg_npm__40smithy_core_3_36_0
  pkg_npm__40aws_sdk_eventstream_handler_node_3_972_36 --> pkg_npm__40smithy_types_4_19_0
  pkg_npm__40aws_sdk_eventstream_handler_node_3_972_36 --> pkg_npm_tslib_2_8_1
  pkg_npm__40aws_sdk_middleware_eventstream_3_972_31 --> pkg_npm__40aws_sdk_types_3_974_6
  pkg_npm__40aws_sdk_middleware_eventstream_3_972_31 --> pkg_npm__40smithy_core_3_36_0
  pkg_npm__40aws_sdk_middleware_eventstream_3_972_31 --> pkg_npm__40smithy_types_4_19_0
  pkg_npm__40aws_sdk_middleware_eventstream_3_972_31 --> pkg_npm_tslib_2_8_1
  pkg_npm__40aws_sdk_middleware_websocket_3_972_56 --> pkg_npm__40aws_sdk_core_3_978_3
  pkg_npm__40aws_sdk_middleware_websocket_3_972_56 --> pkg_npm__40aws_sdk_types_3_974_6
  pkg_npm__40aws_sdk_middleware_websocket_3_972_56 --> pkg_npm__40smithy_core_3_36_0
  pkg_npm__40aws_sdk_middleware_websocket_3_972_56 --> pkg_npm__40smithy_fetch_http_handler_5_8_0
  pkg_npm__40aws_sdk_middleware_websocket_3_972_56 --> pkg_npm__40smithy_signature_v4_5_7_4
  pkg_npm__40aws_sdk_middleware_websocket_3_972_56 --> pkg_npm__40smithy_types_4_19_0
  pkg_npm__40aws_sdk_middleware_websocket_3_972_56 --> pkg_npm_tslib_2_8_1
  pkg_npm__40aws_sdk_token_providers_3_1152_0 --> pkg_npm__40aws_sdk_core_3_978_3
  pkg_npm__40aws_sdk_token_providers_3_1152_0 --> pkg_npm__40aws_sdk_nested_clients_3_997_48
  pkg_npm__40aws_sdk_token_providers_3_1152_0 --> pkg_npm__40aws_sdk_types_3_974_6
  pkg_npm__40aws_sdk_token_providers_3_1152_0 --> pkg_npm__40smithy_core_3_36_0
  pkg_npm__40aws_sdk_token_providers_3_1152_0 --> pkg_npm__40smithy_types_4_19_0
  pkg_npm__40aws_sdk_token_providers_3_1152_0 --> pkg_npm_tslib_2_8_1
  pkg_npm__40aws_sdk_client_bedrock_runtime_3_1152_0 --> pkg_npm__40aws_sdk_core_3_978_3
  pkg_npm__40aws_sdk_client_bedrock_runtime_3_1152_0 --> pkg_npm__40aws_sdk_credential_provider_node_3_972_86
  pkg_npm__40aws_sdk_client_bedrock_runtime_3_1152_0 --> pkg_npm__40aws_sdk_eventstream_handler_node_3_972_36
  pkg_npm__40aws_sdk_client_bedrock_runtime_3_1152_0 --> pkg_npm__40aws_sdk_middleware_eventstream_3_972_31
  pkg_npm__40aws_sdk_client_bedrock_runtime_3_1152_0 --> pkg_npm__40aws_sdk_middleware_websocket_3_972_56
  pkg_npm__40aws_sdk_client_bedrock_runtime_3_1152_0 --> pkg_npm__40aws_sdk_token_providers_3_1152_0
  pkg_npm__40aws_sdk_client_bedrock_runtime_3_1152_0 --> pkg_npm__40aws_sdk_types_3_974_6
  pkg_npm__40aws_sdk_client_bedrock_runtime_3_1152_0 --> pkg_npm__40smithy_core_3_36_0
  pkg_npm__40aws_sdk_client_bedrock_runtime_3_1152_0 --> pkg_npm__40smithy_fetch_http_handler_5_8_0
  pkg_npm__40aws_sdk_client_bedrock_runtime_3_1152_0 --> pkg_npm__40smithy_node_http_handler_4_12_1
  pkg_npm__40aws_sdk_client_bedrock_runtime_3_1152_0 --> pkg_npm__40smithy_types_4_19_0
  pkg_npm__40aws_sdk_client_bedrock_runtime_3_1152_0 --> pkg_npm_tslib_2_8_1
  pkg_npm__40hono_node_server_2_1_5 --> pkg_npm_hono_4_13_13
  pkg_npm_ajv_8_20_0 --> pkg_npm_fast_deep_equal_3_1_3
  pkg_npm_ajv_8_20_0 --> pkg_npm_fast_uri_3_1_8
  pkg_npm_ajv_8_20_0 --> pkg_npm_json_schema_traverse_1_0_0
  pkg_npm_ajv_8_20_0 --> pkg_npm_require_from_string_2_0_2
  pkg_npm_ajv_formats_3_0_1 --> pkg_npm_ajv_8_20_0
  pkg_npm_cors_2_8_6 --> pkg_npm_object_assign_4_1_1
  pkg_npm_cors_2_8_6 --> pkg_npm_vary_1_1_2
  pkg_npm_shebang_command_2_0_0 --> pkg_npm_shebang_regex_3_0_0
  pkg_npm_which_2_0_2 --> pkg_npm_isexe_2_0_0
  pkg_npm_cross_spawn_7_0_6 --> pkg_npm_path_key_3_1_1
  pkg_npm_cross_spawn_7_0_6 --> pkg_npm_shebang_command_2_0_0
  pkg_npm_cross_spawn_7_0_6 --> pkg_npm_which_2_0_2
  pkg_npm_eventsource_3_0_7 --> pkg_npm_eventsource_parser_3_1_1
  pkg_npm_mime_types_3_0_2 --> pkg_npm_mime_db_1_54_0
  pkg_npm_negotiator_1_1_0 --> pkg_npm_content_type_2_1_0
  pkg_npm_accepts_2_0_0 --> pkg_npm_mime_types_3_0_2
  pkg_npm_accepts_2_0_0 --> pkg_npm_negotiator_1_1_0
  pkg_npm_debug_4_4_3 --> pkg_npm_ms_2_1_3
  pkg_npm_http_errors_2_0_1 --> pkg_npm_depd_2_0_0
  pkg_npm_http_errors_2_0_1 --> pkg_npm_inherits_2_0_4
  pkg_npm_http_errors_2_0_1 --> pkg_npm_setprototypeof_1_2_0
  pkg_npm_http_errors_2_0_1 --> pkg_npm_statuses_2_0_2
  pkg_npm_http_errors_2_0_1 --> pkg_npm_toidentifier_1_0_1
  pkg_npm_iconv_lite_0_7_3 --> pkg_npm_safer_buffer_2_1_2
  pkg_npm_on_finished_2_4_1 --> pkg_npm_ee_first_1_1_1
  pkg_npm_side_channel_list_1_0_1 --> pkg_npm_es_errors_1_3_0
  pkg_npm_side_channel_list_1_0_1 --> pkg_npm_object_inspect_1_13_4
  pkg_npm_call_bind_apply_helpers_1_0_2 --> pkg_npm_es_errors_1_3_0
  pkg_npm_call_bind_apply_helpers_1_0_2 --> pkg_npm_function_bind_1_1_2
  pkg_npm_es_object_atoms_1_1_2 --> pkg_npm_es_errors_1_3_0
  pkg_npm_dunder_proto_1_0_1 --> pkg_npm_call_bind_apply_helpers_1_0_2
  pkg_npm_dunder_proto_1_0_1 --> pkg_npm_es_errors_1_3_0
  pkg_npm_dunder_proto_1_0_1 --> pkg_npm_gopd_1_2_0
  pkg_npm_get_proto_1_0_1 --> pkg_npm_dunder_proto_1_0_1
  pkg_npm_get_proto_1_0_1 --> pkg_npm_es_object_atoms_1_1_2
  pkg_npm_hasown_2_0_4 --> pkg_npm_function_bind_1_1_2
  pkg_npm_get_intrinsic_1_3_0 --> pkg_npm_call_bind_apply_helpers_1_0_2
  pkg_npm_get_intrinsic_1_3_0 --> pkg_npm_es_define_property_1_0_1
  pkg_npm_get_intrinsic_1_3_0 --> pkg_npm_es_errors_1_3_0
  pkg_npm_get_intrinsic_1_3_0 --> pkg_npm_es_object_atoms_1_1_2
  pkg_npm_get_intrinsic_1_3_0 --> pkg_npm_function_bind_1_1_2
  pkg_npm_get_intrinsic_1_3_0 --> pkg_npm_get_proto_1_0_1
  pkg_npm_get_intrinsic_1_3_0 --> pkg_npm_gopd_1_2_0
  pkg_npm_get_intrinsic_1_3_0 --> pkg_npm_has_symbols_1_1_0
  pkg_npm_get_intrinsic_1_3_0 --> pkg_npm_hasown_2_0_4
  pkg_npm_get_intrinsic_1_3_0 --> pkg_npm_math_intrinsics_1_1_0
  pkg_npm_call_bound_1_0_4 --> pkg_npm_call_bind_apply_helpers_1_0_2
  pkg_npm_call_bound_1_0_4 --> pkg_npm_get_intrinsic_1_3_0
  pkg_npm_side_channel_map_1_0_1 --> pkg_npm_call_bound_1_0_4
  pkg_npm_side_channel_map_1_0_1 --> pkg_npm_es_errors_1_3_0
  pkg_npm_side_channel_map_1_0_1 --> pkg_npm_get_intrinsic_1_3_0
  pkg_npm_side_channel_map_1_0_1 --> pkg_npm_object_inspect_1_13_4
  pkg_npm_side_channel_weakmap_1_0_2 --> pkg_npm_call_bound_1_0_4
  pkg_npm_side_channel_weakmap_1_0_2 --> pkg_npm_es_errors_1_3_0
  pkg_npm_side_channel_weakmap_1_0_2 --> pkg_npm_get_intrinsic_1_3_0
  pkg_npm_side_channel_weakmap_1_0_2 --> pkg_npm_object_inspect_1_13_4
  pkg_npm_side_channel_weakmap_1_0_2 --> pkg_npm_side_channel_map_1_0_1
  pkg_npm_side_channel_1_1_1 --> pkg_npm_es_errors_1_3_0
  pkg_npm_side_channel_1_1_1 --> pkg_npm_object_inspect_1_13_4
  pkg_npm_side_channel_1_1_1 --> pkg_npm_side_channel_list_1_0_1
  pkg_npm_side_channel_1_1_1 --> pkg_npm_side_channel_map_1_0_1
  pkg_npm_side_channel_1_1_1 --> pkg_npm_side_channel_weakmap_1_0_2
  pkg_npm_qs_6_16_1 --> pkg_npm_es_define_property_1_0_1
  pkg_npm_qs_6_16_1 --> pkg_npm_side_channel_1_1_1
  pkg_npm_raw_body_3_0_2 --> pkg_npm_bytes_3_1_2
  pkg_npm_raw_body_3_0_2 --> pkg_npm_http_errors_2_0_1
  pkg_npm_raw_body_3_0_2 --> pkg_npm_iconv_lite_0_7_3
  pkg_npm_raw_body_3_0_2 --> pkg_npm_unpipe_1_0_0
  pkg_npm_type_is_2_1_0 --> pkg_npm_content_type_2_1_0
  pkg_npm_type_is_2_1_0 --> pkg_npm_media_typer_1_1_1
  pkg_npm_type_is_2_1_0 --> pkg_npm_mime_types_3_0_2
  pkg_npm_body_parser_2_3_0 --> pkg_npm_bytes_3_1_2
  pkg_npm_body_parser_2_3_0 --> pkg_npm_content_type_2_1_0
  pkg_npm_body_parser_2_3_0 --> pkg_npm_debug_4_4_3
  pkg_npm_body_parser_2_3_0 --> pkg_npm_http_errors_2_0_1
  pkg_npm_body_parser_2_3_0 --> pkg_npm_iconv_lite_0_7_3
  pkg_npm_body_parser_2_3_0 --> pkg_npm_on_finished_2_4_1
  pkg_npm_body_parser_2_3_0 --> pkg_npm_qs_6_16_1
  pkg_npm_body_parser_2_3_0 --> pkg_npm_raw_body_3_0_2
  pkg_npm_body_parser_2_3_0 --> pkg_npm_type_is_2_1_0
  pkg_npm_finalhandler_2_1_1 --> pkg_npm_debug_4_4_3
  pkg_npm_finalhandler_2_1_1 --> pkg_npm_encodeurl_2_0_0
  pkg_npm_finalhandler_2_1_1 --> pkg_npm_escape_html_1_0_3
  pkg_npm_finalhandler_2_1_1 --> pkg_npm_on_finished_2_4_1
  pkg_npm_finalhandler_2_1_1 --> pkg_npm_parseurl_1_3_3
  pkg_npm_finalhandler_2_1_1 --> pkg_npm_statuses_2_0_2
  pkg_npm_once_1_4_0 --> pkg_npm_wrappy_1_0_2
  pkg_npm_proxy_addr_2_0_8 --> pkg_npm_forwarded_0_2_0
  pkg_npm_proxy_addr_2_0_8 --> pkg_npm_ipaddr_js_1_9_1
  pkg_npm_router_2_2_0 --> pkg_npm_debug_4_4_3
  pkg_npm_router_2_2_0 --> pkg_npm_depd_2_0_0
  pkg_npm_router_2_2_0 --> pkg_npm_is_promise_4_0_0
  pkg_npm_router_2_2_0 --> pkg_npm_parseurl_1_3_3
  pkg_npm_router_2_2_0 --> pkg_npm_path_to_regexp_8_4_2
  pkg_npm_send_1_2_1 --> pkg_npm_debug_4_4_3
  pkg_npm_send_1_2_1 --> pkg_npm_encodeurl_2_0_0
  pkg_npm_send_1_2_1 --> pkg_npm_escape_html_1_0_3
  pkg_npm_send_1_2_1 --> pkg_npm_etag_1_8_1
  pkg_npm_send_1_2_1 --> pkg_npm_fresh_2_0_0
  pkg_npm_send_1_2_1 --> pkg_npm_http_errors_2_0_1
  pkg_npm_send_1_2_1 --> pkg_npm_mime_types_3_0_2
  pkg_npm_send_1_2_1 --> pkg_npm_ms_2_1_3
  pkg_npm_send_1_2_1 --> pkg_npm_on_finished_2_4_1
  pkg_npm_send_1_2_1 --> pkg_npm_range_parser_1_3_0
  pkg_npm_send_1_2_1 --> pkg_npm_statuses_2_0_2
  pkg_npm_serve_static_2_2_1 --> pkg_npm_encodeurl_2_0_0
  pkg_npm_serve_static_2_2_1 --> pkg_npm_escape_html_1_0_3
  pkg_npm_serve_static_2_2_1 --> pkg_npm_parseurl_1_3_3
  pkg_npm_serve_static_2_2_1 --> pkg_npm_send_1_2_1
  pkg_npm_express_5_3_0 --> pkg_npm_accepts_2_0_0
  pkg_npm_express_5_3_0 --> pkg_npm_body_parser_2_3_0
  pkg_npm_express_5_3_0 --> pkg_npm_content_disposition_2_0_1
  pkg_npm_express_5_3_0 --> pkg_npm_content_type_2_1_0
  pkg_npm_express_5_3_0 --> pkg_npm_cookie_signature_1_2_2
  pkg_npm_express_5_3_0 --> pkg_npm_cookie_0_7_2
  pkg_npm_express_5_3_0 --> pkg_npm_debug_4_4_3
  pkg_npm_express_5_3_0 --> pkg_npm_depd_2_0_0
  pkg_npm_express_5_3_0 --> pkg_npm_encodeurl_2_0_0
  pkg_npm_express_5_3_0 --> pkg_npm_escape_html_1_0_3
  pkg_npm_express_5_3_0 --> pkg_npm_etag_1_8_1
  pkg_npm_express_5_3_0 --> pkg_npm_finalhandler_2_1_1
  pkg_npm_express_5_3_0 --> pkg_npm_fresh_2_0_0
  pkg_npm_express_5_3_0 --> pkg_npm_http_errors_2_0_1
  pkg_npm_express_5_3_0 --> pkg_npm_merge_descriptors_2_0_0
  pkg_npm_express_5_3_0 --> pkg_npm_mime_types_3_0_2
  pkg_npm_express_5_3_0 --> pkg_npm_on_finished_2_4_1
  pkg_npm_express_5_3_0 --> pkg_npm_once_1_4_0
  pkg_npm_express_5_3_0 --> pkg_npm_parseurl_1_3_3
  pkg_npm_express_5_3_0 --> pkg_npm_proxy_addr_2_0_8
  pkg_npm_express_5_3_0 --> pkg_npm_qs_6_16_1
  pkg_npm_express_5_3_0 --> pkg_npm_range_parser_1_3_0
  pkg_npm_express_5_3_0 --> pkg_npm_router_2_2_0
  pkg_npm_express_5_3_0 --> pkg_npm_send_1_2_1
  pkg_npm_express_5_3_0 --> pkg_npm_serve_static_2_2_1
  pkg_npm_express_5_3_0 --> pkg_npm_statuses_2_0_2
  pkg_npm_express_5_3_0 --> pkg_npm_type_is_2_1_0
  pkg_npm_express_5_3_0 --> pkg_npm_vary_1_1_2
  pkg_npm_express_rate_limit_8_7_1 --> pkg_npm_debug_4_4_3
  pkg_npm_express_rate_limit_8_7_1 --> pkg_npm_express_5_3_0
  pkg_npm_express_rate_limit_8_7_1 --> pkg_npm_ip_address_10_7_4
  pkg_npm_zod_to_json_schema_3_25_2 --> pkg_npm_zod_4_6_7
  pkg_npm__40modelcontextprotocol_sdk_1_32_1 --> pkg_npm__40hono_node_server_2_1_5
  pkg_npm__40modelcontextprotocol_sdk_1_32_1 --> pkg_npm_ajv_formats_3_0_1
  pkg_npm__40modelcontextprotocol_sdk_1_32_1 --> pkg_npm_ajv_8_20_0
  pkg_npm__40modelcontextprotocol_sdk_1_32_1 --> pkg_npm_content_type_1_0_5
  pkg_npm__40modelcontextprotocol_sdk_1_32_1 --> pkg_npm_cors_2_8_6
  pkg_npm__40modelcontextprotocol_sdk_1_32_1 --> pkg_npm_cross_spawn_7_0_6
  pkg_npm__40modelcontextprotocol_sdk_1_32_1 --> pkg_npm_eventsource_parser_3_1_1
  pkg_npm__40modelcontextprotocol_sdk_1_32_1 --> pkg_npm_eventsource_3_0_7
  pkg_npm__40modelcontextprotocol_sdk_1_32_1 --> pkg_npm_express_rate_limit_8_7_1
  pkg_npm__40modelcontextprotocol_sdk_1_32_1 --> pkg_npm_express_5_3_0
  pkg_npm__40modelcontextprotocol_sdk_1_32_1 --> pkg_npm_hono_4_13_13
  pkg_npm__40modelcontextprotocol_sdk_1_32_1 --> pkg_npm_jose_6_2_12
  pkg_npm__40modelcontextprotocol_sdk_1_32_1 --> pkg_npm_json_schema_typed_8_0_2
  pkg_npm__40modelcontextprotocol_sdk_1_32_1 --> pkg_npm_pkce_challenge_5_0_1
  pkg_npm__40modelcontextprotocol_sdk_1_32_1 --> pkg_npm_raw_body_3_0_2
  pkg_npm__40modelcontextprotocol_sdk_1_32_1 --> pkg_npm_zod_to_json_schema_3_25_2
  pkg_npm__40modelcontextprotocol_sdk_1_32_1 --> pkg_npm_zod_4_6_7
  pkg_npm__40types_node_26_6_5 --> pkg_npm_undici_types_8_9_0
  pkg_npm__40types_connect_3_4_38 --> pkg_npm__40types_node_26_6_5
  pkg_npm__40types_body_parser_1_19_6 --> pkg_npm__40types_connect_3_4_38
  pkg_npm__40types_body_parser_1_19_6 --> pkg_npm__40types_node_26_6_5
  pkg_npm__40types_send_1_2_1 --> pkg_npm__40types_node_26_6_5
  pkg_npm__40types_express_serve_static_core_5_1_3 --> pkg_npm__40types_node_26_6_5
  pkg_npm__40types_express_serve_static_core_5_1_3 --> pkg_npm__40types_qs_6_15_1
  pkg_npm__40types_express_serve_static_core_5_1_3 --> pkg_npm__40types_range_parser_1_2_7
  pkg_npm__40types_express_serve_static_core_5_1_3 --> pkg_npm__40types_send_1_2_1
  pkg_npm__40types_serve_static_2_2_0 --> pkg_npm__40types_http_errors_2_0_5
  pkg_npm__40types_serve_static_2_2_0 --> pkg_npm__40types_node_26_6_5
  pkg_npm__40types_express_5_0_6 --> pkg_npm__40types_body_parser_1_19_6
  pkg_npm__40types_express_5_0_6 --> pkg_npm__40types_express_serve_static_core_5_1_3
  pkg_npm__40types_express_5_0_6 --> pkg_npm__40types_serve_static_2_2_0
  pkg_npm_esbuild_0_28_2 --> pkg_npm__40esbuild_aix_ppc64_0_28_2
  pkg_npm_esbuild_0_28_2 --> pkg_npm__40esbuild_android_arm64_0_28_2
  pkg_npm_esbuild_0_28_2 --> pkg_npm__40esbuild_android_arm_0_28_2
  pkg_npm_esbuild_0_28_2 --> pkg_npm__40esbuild_android_x64_0_28_2
  pkg_npm_esbuild_0_28_2 --> pkg_npm__40esbuild_darwin_arm64_0_28_2
  pkg_npm_esbuild_0_28_2 --> pkg_npm__40esbuild_darwin_x64_0_28_2
  pkg_npm_esbuild_0_28_2 --> pkg_npm__40esbuild_freebsd_arm64_0_28_2
  pkg_npm_esbuild_0_28_2 --> pkg_npm__40esbuild_freebsd_x64_0_28_2
  pkg_npm_esbuild_0_28_2 --> pkg_npm__40esbuild_linux_arm64_0_28_2
  pkg_npm_esbuild_0_28_2 --> pkg_npm__40esbuild_linux_arm_0_28_2
  pkg_npm_esbuild_0_28_2 --> pkg_npm__40esbuild_linux_ia32_0_28_2
  pkg_npm_esbuild_0_28_2 --> pkg_npm__40esbuild_linux_loong64_0_28_2
  pkg_npm_esbuild_0_28_2 --> pkg_npm__40esbuild_linux_mips64el_0_28_2
  pkg_npm_esbuild_0_28_2 --> pkg_npm__40esbuild_linux_ppc64_0_28_2
  pkg_npm_esbuild_0_28_2 --> pkg_npm__40esbuild_linux_riscv64_0_28_2
  pkg_npm_esbuild_0_28_2 --> pkg_npm__40esbuild_linux_s390x_0_28_2
  pkg_npm_esbuild_0_28_2 --> pkg_npm__40esbuild_linux_x64_0_28_2
  pkg_npm_esbuild_0_28_2 --> pkg_npm__40esbuild_netbsd_arm64_0_28_2
  pkg_npm_esbuild_0_28_2 --> pkg_npm__40esbuild_netbsd_x64_0_28_2
  pkg_npm_esbuild_0_28_2 --> pkg_npm__40esbuild_openbsd_arm64_0_28_2
  pkg_npm_esbuild_0_28_2 --> pkg_npm__40esbuild_openbsd_x64_0_28_2
  pkg_npm_esbuild_0_28_2 --> pkg_npm__40esbuild_openharmony_arm64_0_28_2
  pkg_npm_esbuild_0_28_2 --> pkg_npm__40esbuild_sunos_x64_0_28_2
  pkg_npm_esbuild_0_28_2 --> pkg_npm__40esbuild_win32_arm64_0_28_2
  pkg_npm_esbuild_0_28_2 --> pkg_npm__40esbuild_win32_ia32_0_28_2
  pkg_npm_esbuild_0_28_2 --> pkg_npm__40esbuild_win32_x64_0_28_2
  pkg_npm_tsx_4_23_15 --> pkg_npm_esbuild_0_28_2
  pkg_npm_tsx_4_23_15 --> pkg_npm_fsevents_2_3_3
  pkg_npm_typescript_7_0_2 --> pkg_npm__40typescript_typescript_aix_ppc64_7_0_2
  pkg_npm_typescript_7_0_2 --> pkg_npm__40typescript_typescript_darwin_arm64_7_0_2
  pkg_npm_typescript_7_0_2 --> pkg_npm__40typescript_typescript_darwin_x64_7_0_2
  pkg_npm_typescript_7_0_2 --> pkg_npm__40typescript_typescript_freebsd_arm64_7_0_2
  pkg_npm_typescript_7_0_2 --> pkg_npm__40typescript_typescript_freebsd_x64_7_0_2
  pkg_npm_typescript_7_0_2 --> pkg_npm__40typescript_typescript_linux_arm64_7_0_2
  pkg_npm_typescript_7_0_2 --> pkg_npm__40typescript_typescript_linux_arm_7_0_2
  pkg_npm_typescript_7_0_2 --> pkg_npm__40typescript_typescript_linux_loong64_7_0_2
  pkg_npm_typescript_7_0_2 --> pkg_npm__40typescript_typescript_linux_mips64el_7_0_2
  pkg_npm_typescript_7_0_2 --> pkg_npm__40typescript_typescript_linux_ppc64_7_0_2
  pkg_npm_typescript_7_0_2 --> pkg_npm__40typescript_typescript_linux_riscv64_7_0_2
  pkg_npm_typescript_7_0_2 --> pkg_npm__40typescript_typescript_linux_s390x_7_0_2
  pkg_npm_typescript_7_0_2 --> pkg_npm__40typescript_typescript_linux_x64_7_0_2
  pkg_npm_typescript_7_0_2 --> pkg_npm__40typescript_typescript_netbsd_arm64_7_0_2
  pkg_npm_typescript_7_0_2 --> pkg_npm__40typescript_typescript_netbsd_x64_7_0_2
  pkg_npm_typescript_7_0_2 --> pkg_npm__40typescript_typescript_openbsd_arm64_7_0_2
  pkg_npm_typescript_7_0_2 --> pkg_npm__40typescript_typescript_openbsd_x64_7_0_2
  pkg_npm_typescript_7_0_2 --> pkg_npm__40typescript_typescript_sunos_x64_7_0_2
  pkg_npm_typescript_7_0_2 --> pkg_npm__40typescript_typescript_win32_arm64_7_0_2
  pkg_npm_typescript_7_0_2 --> pkg_npm__40typescript_typescript_win32_x64_7_0_2
  pkg_npm__40aws_sdk_credential_provider_sso_3_973_18 --> pkg_npm__40aws_sdk_token_providers_3_1152_0
  pkg_npm__40modelcontextprotocol_sdk_1_32_1 --> pkg_npm_content_type_2_1_0
  classDef vuln fill:#fde2e2,stroke:#c0392b
  classDef anomaly fill:#fdebd0,stroke:#d35400
  class pkg_npm__40hono_node_server_2_1_5 vuln
  class pkg_npm_body_parser_2_3_0 vuln
  class pkg_npm_fast_uri_3_1_8 vuln
  class pkg_npm_hono_4_13_13 vuln
  class file__Users_rithvikrajesh_Projects_Dummies_Software_Supply_Chain_Guardian_Team_31_data_scans_vignes_vm__udhaar_mcp__20261124_061141_repo_Dockerfile anomaly
  class file_Dockerfile anomaly
  class pkg_npm_cors_2_8_6 anomaly
  class pkg_npm_esbuild_0_28_2 anomaly
  class pkg_npm_fsevents_2_3_3 anomaly
```

## Remediation plans

| Component | Action | Target | Attempt | Status | Rationale |
|---|---|---|---|---|---|
| Dockerfile | pin |  | 1 | proposed | Pin the base image by @sha256 digest (and move off EOL tags). |
| file:Dockerfile | fix_config |  | 1 | proposed | Apply the fix described by the failed Trivy check. Add HEALTHCHECK instruction in Dockerfi |
| node-server@2.1.5 | upgrade | 2.1.6 | 1 | proposed | minimal: @hono/node-server 2.1.6 re-scanned clean on the registry (0 known advisories) |
| hono@4.13.13 | upgrade | 4.13.16 | 1 | proposed | minimal: hono 4.13.16 re-scanned clean on the registry (0 known advisories) |
| fast-uri@3.1.8 | upgrade | 3.1.9 | 1 | proposed | co-upgrade: ajv 8.20.0 requires fast-uri ^3.0.1 |
| body-parser@2.3.0 | upgrade | 2.4.0 | 1 | proposed | minimal: body-parser 2.4.0 re-scanned clean on the registry (0 known advisories) |
| cors@2.8.6 | remove |  | 1 | proposed | Remove or replace with the intended package after review. Signals: typosquat_suspect. |

## Validation


## Source coverage

- discovery: SBOM CycloneDX 1.7: 181 components; package-lock v3: 184 packages
- reputation: 12 ok, 0 failed
- source:pypi-osv: ok
- source:npm-audit: ok
- source:osv: ok
- source:osv-scanner: ok
- source:trivy: ok
- source:grype: ok
- source:ghsa: skipped: set GITHUB_TOKEN (unauthenticated limit is 60 req/h)
- source:cisa-kev: ok (1792 entries)
- source:epss: ok (12/12)
- llm: ok via ['groq']

## Agent trace

 1. **supervisor** → ['discovery', 'cicd']: policy: ready=['discovery', 'cicd'], handoffs=[]
 1. **cicd** → supervisor: 2 container/CI findings in 1 files; Trivy: 1 misconfigurations, 0 secrets (values redacted)
 1. **discovery** → supervisor: 181 components (8 direct), 361 edges; SBOM CycloneDX 1.7: 181 components; package-lock v3: 184 packages
 2. **supervisor** → ['vuln_intel', 'reputation', 'reachability']: policy: ready=['vuln_intel', 'reputation', 'reachability'], handoffs=[]
 2. **reachability** → supervisor: reachability: {'imported': 4, 'used_transitively': 116, 'not_imported': 61}
 2. **reputation** → supervisor: registry metadata for 12 packages
 2. **vuln_intel** → supervisor: 67 raw advisory records from 6/6 sources -> 12 unique vulnerabilities on 4 packages (hono@4.13.13=5, fast-uri@3.1.8=4, node-server@2.1.5=2, body-parser@2.3.0=1)
 3. **supervisor** → ['exploit_intel', 'anomaly']: policy: ready=['exploit_intel', 'anomaly'], handoffs=[]
 3. **anomaly** → supervisor: 3 non-CVE findings: {'typosquat_suspect': 1, 'install_script': 2}
 3. **anomaly** → reachability: handoff: suspicious packages found; check whether source code imports them
 3. **exploit_intel** → supervisor: 12 CVEs checked: 0 in CISA KEV, EPSS for 12
 4. **supervisor** → ['reachability']: policy: ready=['scoring'], handoffs=['reachability']
 4. **reachability** → supervisor: reachability: {'imported': 4, 'used_transitively': 116, 'not_imported': 61}; handoff check on 1 suspicious packages: imported by source = none
 5. **supervisor** → ['scoring']: policy: ready=['scoring'], handoffs=[]
 5. **scoring** → supervisor: scored 18 findings; top: CVE-2026-111181 on body-parser@2.3.0 = 31.4; TYPOSQUAT_SUSPECT on cors@2.8.6 = 28.0; CVE-2026-126343 on node-server@2.1.5 = 26.0
 6. **supervisor** → ['remediation']: policy: ready=['remediation'], handoffs=[]
 6. **remediation** → supervisor: 7 plans (strategy=minimal): upgrades [@hono/node-server 2.1.5->2.1.6, hono 4.13.13->4.13.16, fast-uri 3.1.8->3.1.9, body-parser 2.3.0->2.4.0]; other actions {'pin': 1, 'fix_config': 1, 'remove': 1}; resolver: fast-uri -> 3.1.9 to satisfy ajv ^3.0.1
 7. **supervisor** → ['explainer']: policy: ready=['explainer'], handoffs=[]
 7. **explainer** → supervisor: LLM produced 13 evidence-cited claims for 14 findings  [33.5s]
 8. **supervisor** → ['critic']: policy: ready=['critic'], handoffs=[]
 8. **critic** → supervisor: verified 13 claims; 0 replaced by templates
 9. **supervisor** → report: finish: no agent has new inputs and no handoffs are open