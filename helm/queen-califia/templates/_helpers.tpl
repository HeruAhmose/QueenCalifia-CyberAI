{{/*
Common helpers for the queen-califia chart.
*/}}

{{- define "queen-califia.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "queen-califia.fullname" -}}
{{- if .Values.fullnameOverride -}}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- $name := include "queen-califia.name" . -}}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}

{{- define "queen-califia.labels" -}}
app.kubernetes.io/name: {{ include "queen-califia.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version | quote }}
{{- end -}}

{{- define "queen-califia.selectorLabels" -}}
app.kubernetes.io/name: {{ include "queen-califia.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}

{{- define "queen-califia.ns" -}}
{{- if .Values.namespace.name -}}
{{- .Values.namespace.name -}}
{{- else -}}
{{- .Release.Namespace -}}
{{- end -}}
{{- end -}}

{{/*
Image reference: digest takes priority over tag for immutable deploys.
Usage: {{ include "queen-califia.image" (dict "img" .Values.api.image) }}
*/}}
{{- define "queen-califia.image" -}}
{{- $img := .img -}}
{{- if $img.digest -}}
{{- printf "%s@%s" $img.repository $img.digest -}}
{{- else -}}
{{- printf "%s:%s" $img.repository ($img.tag | default "latest") -}}
{{- end -}}
{{- end -}}

{{/*
Worker image: falls back to API image when worker image fields are empty.
*/}}
{{- define "queen-califia.workerImage" -}}
{{- $repo := default .Values.api.image.repository .Values.worker.image.repository -}}
{{- $digest := default .Values.api.image.digest .Values.worker.image.digest -}}
{{- $tag := default .Values.api.image.tag .Values.worker.image.tag -}}
{{- if $digest -}}
{{- printf "%s@%s" $repo $digest -}}
{{- else -}}
{{- printf "%s:%s" $repo ($tag | default "latest") -}}
{{- end -}}
{{- end -}}
