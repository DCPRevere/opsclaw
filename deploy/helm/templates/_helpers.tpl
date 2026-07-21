{{/*
Expand the name of the chart.
*/}}
{{- define "opsclaw.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create a default fully qualified app name.
*/}}
{{- define "opsclaw.fullname" -}}
{{- if .Values.fullnameOverride }}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- $name := default .Chart.Name .Values.nameOverride }}
{{- if contains $name .Release.Name }}
{{- .Release.Name | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" }}
{{- end }}
{{- end }}
{{- end }}

{{- define "opsclaw.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Common labels.
*/}}
{{- define "opsclaw.labels" -}}
helm.sh/chart: {{ include "opsclaw.chart" . }}
{{ include "opsclaw.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{/*
Selector labels.
*/}}
{{- define "opsclaw.selectorLabels" -}}
app.kubernetes.io/name: {{ include "opsclaw.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/*
Service account name.
*/}}
{{- define "opsclaw.serviceAccountName" -}}
{{- if .Values.serviceAccount.create }}
{{- default (include "opsclaw.fullname" .) .Values.serviceAccount.name }}
{{- else }}
{{- default "default" .Values.serviceAccount.name }}
{{- end }}
{{- end }}

{{/*
PriorityClass name.
*/}}
{{- define "opsclaw.priorityClassName" -}}
{{- if .Values.priorityClassName.name }}
{{- .Values.priorityClassName.name }}
{{- else }}
{{- printf "%s-critical" (include "opsclaw.fullname" .) }}
{{- end }}
{{- end }}

{{/*
Image reference: repository:tag, tag defaults to Chart.AppVersion.
*/}}
{{- define "opsclaw.image" -}}
{{- $tag := .Values.image.tag | default .Chart.AppVersion }}
{{- printf "%s:%s" .Values.image.repository $tag }}
{{- end }}

{{/*
PVC claim name: existingClaim if set, else "<fullname>-data".
*/}}
{{- define "opsclaw.pvcName" -}}
{{- if .Values.persistence.existingClaim }}
{{- .Values.persistence.existingClaim }}
{{- else }}
{{- printf "%s-data" (include "opsclaw.fullname" .) }}
{{- end }}
{{- end }}

{{/*
Required-value guard for the external dead-man heartbeat (DESIGN.md §4, §5:
"mandatory for in-cluster installs" — nothing inside a dead cluster can
report the cluster is dead, so shipping this chart with the heartbeat unset
would silently ship the one placement that most needs it disabled). Fails
template rendering with a clear message rather than installing a
half-configured daemon.
*/}}
{{- define "opsclaw.requireDeadmanUrl" -}}
{{- if not .Values.deadmanUrl }}
{{- fail "opsclaw: .Values.deadmanUrl is required for the in-cluster Helm install (DESIGN.md §5: the external dead-man heartbeat is mandatory in this placement — nothing inside a dead cluster can report that the cluster is dead). Set --set deadmanUrl=https://... to a heartbeat receiver outside this cluster (healthchecks.io, a PagerDuty heartbeat, or any webhook outside this failure domain)." }}
{{- end }}
{{- end }}
