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
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// EDIT THIS FILE!  THIS IS SCAFFOLDING FOR YOU TO OWN!
// NOTE: json tags are required.  Any new fields you add must have json tags for the fields to be serialized.

// UserBindingSpec defines the desired state of UserBinding.
type UserBindingSpec struct {
	// 关联的用户名
	User  string `json:"user,omitempty"`
	Scope Scope  `json:"scope,omitempty"`
	// 对应权限名称Clusterrole或role
	Role string `json:"role,omitempty"`
}

type Scope struct {
	// 权限类别支持Cluster、Workspace和Namespace三种
	Kind string `json:"kind,omitempty"`
	// Kind为Cluster是随便填写，Workspace和Namespace则填写对应的名称
	Name string `json:"name,omitempty"`
}

// UserBindingStatus defines the observed state of UserBinding.
type UserBindingStatus struct {
	// 是否成功下发RBAC资源（RoleBinding/ClusterRoleBinding）
	Synced bool `json:"synced,omitempty"`
	// 是否要求撤销权限（即计划回收）由上游（比如User被禁用）主动设置true
	Revoked bool `json:"revoked,omitempty"`
	// 权限是否已经被成功回收， cleanupRBAC成功后设置为true
	// RevokeComplete bool `json:"revokeComplete,omitempty"`
	// 最后一次成功同步RBAC的时间戳，用来做审计、前端展示
	LastSyncTime metav1.Time `json:"lastSyncTime,omitempty"`
	// 上一次失败的错误信息，如果applyRBAC/cleanupRBAC出错，记录下来方便排查
	// LastErrorReason string `json:"lastErrorReason,omitempty"`
	// 用于记录最后同步信息
	LastTransitionMsg string `json:"lastTransitionMsg,omitempty"` // 🌟 新增字段
	// LastAppliedGeneration is the generation of the last applied configuration
	LastAppliedGeneration int64 `json:"lastAppliedGeneration,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:path=userbindings,scope=Cluster
// +kubebuilder:printcolumn:name="User",type="string",JSONPath=".spec.user"
// +kubebuilder:printcolumn:name="Role",type="string",JSONPath=".spec.role"
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`
// UserBinding is the Schema for the userbindings API.
type UserBinding struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   UserBindingSpec   `json:"spec,omitempty"`
	Status UserBindingStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// UserBindingList contains a list of UserBinding.
type UserBindingList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []UserBinding `json:"items"`
}

func init() {
	SchemeBuilder.Register(&UserBinding{}, &UserBindingList{})
}
