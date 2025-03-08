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
	v1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// RoleTemplateSpec 定义了 RoleTemplate 的期望状态
type RoleTemplateSpec struct {
	// 是否自动应用到新建的 namespace
	AutoApply bool `json:"autoApply"`

	// DefaultRoles 在所有符合条件的 namespace 中自动下发
	DefaultRoles DefaultOrCustomRoles `json:"defaultRoles,omitempty"`

	// CustomRoles 允许用户自定义角色，并在符合条件的 namespace 下发
	CustomRoles DefaultOrCustomRoles `json:"customRoles,omitempty"`
}

// RoleSyncConfig 用于定义角色下发规则
type DefaultOrCustomRoles struct {
	// 需要下发的 namespace 列表，支持 * 代表所有 namespace
	Namespaces []string `json:"namespaces"`

	// 排除的 namespace 列表
	ExcludedNamespaces []string `json:"excludedNamespaces,omitempty"`

	// 角色定义
	Roles []TemplateRole `json:"roles,omitempty"`
}

// RoleDefinition 定义角色名称及其规则
type TemplateRole struct {
	// 角色名称
	// DefaultRoles 下发后的role名称则是该名称
	// CustomRoles 下发后的role名称则是 roleTemplate模板名称+该规则名称
	Name string `json:"name"`

	// 角色规则
	Rules []v1.PolicyRule `json:"rules"`
}

// RoleTemplateStatus 记录已应用的 namespace 信息
type RoleTemplateStatus struct {
	// 记录 DefaultRoles 已应用的 namespace
	AppliedDefaultRolesNamespace []string `json:"appliedDefaultRolesNamespace,omitempty"`

	// 记录 CustomRoles 已应用的 namespace
	AppliedCustomRolesNamespace []string `json:"appliedCustomRolesNamespace,omitempty"`

	// 记录修改时间
	LastUpdateTime metav1.Time `json:"lastUpdateTime,omitempty"`
	// 记录最后一次应用的配置版本
	LastAppliedGeneration int64 `json:"lastAppliedGeneration,omitempty"`
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
