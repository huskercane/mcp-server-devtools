{{- define "mcp.fullname" -}}
{{- printf "%s-mcp-devtools" .Release.Name | trunc 50 | trimSuffix "-" -}}
{{- end -}}
{{- define "mcp.image" -}}
{{- if .Values.image.digest -}}
{{- printf "%s@%s" .Values.image.repository .Values.image.digest -}}
{{- else -}}
{{- printf "%s:%s" .Values.image.repository (default (printf "v%s" .Chart.AppVersion) .Values.image.tag) -}}
{{- end -}}
{{- end -}}
