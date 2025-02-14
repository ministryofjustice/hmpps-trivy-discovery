{{- define "discoveryCronJob.envs" -}}
{{- if or .discoveryCronJob.namespace_secrets .discoveryCronJob.env .discoveryCronJob.elasticache-redis -}}
env:
{{- if .discoveryCronJob.namespace_secrets -}}
{{- range $secret, $envs := .discoveryCronJob.namespace_secrets }}
  {{- range $key, $val := $envs }}
  - name: {{ $key }}
    valueFrom:
      secretKeyRef:
        key: {{ trimSuffix "?" $val }}
        name: {{ $secret }}{{ if hasSuffix "?" $val }}
        optional: true{{ end }}  {{- end }}
{{- end }}
{{- end }}
{{- if .discoveryCronJob.env -}}
{{- range $key, $val := .discoveryCronJob.env }}
  - name: {{ $key }}
    value: {{ $val }}
{{- end }}
{{- end }}
{{- if .discoveryCronJob.elasticache-redis -}}
{{- range $secret, $envs := .discoveryCronJob.elasticache-redis }}
  {{- range $key, $val := $envs }}
  - name: {{ $key }}
    valueFrom:
      secretKeyRef:
        key: {{ trimSuffix "?" $val }}
        name: {{ $secret }}{{ if hasSuffix "?" $val }}
        optional: true{{ end }}  {{- end }}
{{- end }}
{{- end }}
{{- end }}
{{- end -}}
{{- end -}}
