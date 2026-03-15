{{- define "tls-tracer.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{- define "tls-tracer.fullname" -}}
{{- $prefix := default "" .Values.companyPrefix }}
{{- if .Values.fullnameOverride }}
{{- printf "%s%s" $prefix .Values.fullnameOverride | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- $name := default .Chart.Name .Values.nameOverride }}
{{- if contains $name .Release.Name }}
{{- printf "%s%s" $prefix .Release.Name | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- printf "%s%s-%s" $prefix .Release.Name $name | trunc 63 | trimSuffix "-" }}
{{- end }}
{{- end }}
{{- end }}

{{- define "tls-tracer.labels" -}}
helm.sh/chart: {{ .Chart.Name }}-{{ .Chart.Version | replace "+" "_" }}
app.kubernetes.io/name: {{ include "tls-tracer.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{- define "tls-tracer.selectorLabels" -}}
app.kubernetes.io/name: {{ include "tls-tracer.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{- define "tls-tracer.serviceAccountName" -}}
{{- $prefix := default "" .Values.companyPrefix }}
{{- if .Values.serviceAccount.create }}
{{- default (include "tls-tracer.fullname" .) .Values.serviceAccount.name }}
{{- else }}
{{- default "default" .Values.serviceAccount.name }}
{{- end }}
{{- end }}
