{{- define "discoveryCronJob.envs" -}}
{{- if .discoveryCronJob.namespace_secrets -}}
env:
{{- range $secret, $envs := .discoveryCronJob.namespace_secrets }}
  {{- range $key, $val := $envs }}
  - name: {{ $key }}
    valueFrom:
      secretKeyRef:
        key: {{ trimSuffix "?" $val }}
        name: {{ $secret }}{{ if hasSuffix "?" $val }}
        optional: true{{ end }}  {{- end }}
{{- end }}
{{- end -}}
{{- end -}}
