/*
Copyright 2025.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package v1beta1

import (
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type RoleTemplateSpec struct {
	AutoApply          bool                  `json:"autoApply"`
	Namespaces         []string              `json:"namespaces,omitempty"`
	NamespaceSelector  *metav1.LabelSelector `json:"namespaceSelector,omitempty"`
	ExcludedNamespaces []string              `json:"excludedNamespaces,omitempty"`
	Rules              []rbacv1.PolicyRule   `json:"rules"`
}

type RoleTemplateStatus struct {
	AppliedNamespaces     []string    `json:"appliedNamespaces,omitempty"`
	LastUpdateTime        metav1.Time `json:"lastUpdateTime,omitempty"`
	LastAppliedGeneration int64       `json:"lastAppliedGeneration,omitempty"`
}

// RoleTemplate 是 RoleTemplate 的 Schema 定义
// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:path=roletemplates,scope=Cluster
// +kubebuilder:printcolumn:name="AutoApply",type=boolean,JSONPath=`.spec.autoApply`
// +kubebuilder:printcolumn:name="UpdatedAt",type=date,JSONPath=`.status.lastUpdateTime`
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`
type RoleTemplate struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   RoleTemplateSpec   `json:"spec,omitempty"`
	Status RoleTemplateStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true
// RoleTemplateList 包含多个 RoleTemplate
type RoleTemplateList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []RoleTemplate `json:"items"`
}

func init() {
	SchemeBuilder.Register(&RoleTemplate{}, &RoleTemplateList{})
}
