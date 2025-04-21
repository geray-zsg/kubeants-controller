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

// RoleBinding defines a role binding for a user in a namespace or set of namespaces
type RoleBinding struct {
	// Name of the role binding
	Name string `json:"name,omitempty"`
	// Namespaces specifies the namespaces for the role binding
	Namespaces []string `json:"namespaces,omitempty"`
	// NamespaceSelector selects namespaces based on labels
	NamespaceSelector *metav1.LabelSelector `json:"namespaceSelector,omitempty"`
}

// RoleBinding defines a role binding for a user in a namespace or set of namespaces
type Roles struct {
	// Name of the role binding
	Name string `json:"name,omitempty"`
	// Namespaces specifies the namespaces for the role binding
	Namespaces []string `json:"namespaces,omitempty"`
	// NamespaceSelector selects namespaces based on labels
	NamespaceSelector *metav1.LabelSelector `json:"namespaceSelector,omitempty"`
}

// UserSpec defines the desired state of User.
type UserSpec struct {
	// State indicates the status of the user (e.g., Active, Inactive)
	State string `json:"state,omitempty"`
	// Name is the display name of the user
	Name string `json:"name,omitempty"`
	// 绑定的平台角色
	PlatformRoles string `json:"platformRoles,omitempty"`
	// Email is the email address of the user
	Email string `json:"email,omitempty"`
	// Phone is the phone number of the user
	Phone string `json:"phone,omitempty"`
	// Password is the hashed password of the user (not typically stored in a CRD, for security reasons)
	Password string `json:"password,omitempty"`
	// ClusterRoles specifies the cluster-wide role binding for the user
	ClusterRoles []string `json:"clusterroles,omitempty"`
	// Roles specifies the cluster-wide role binding for the user
	Roles []Roles `json:"roles,omitempty"`
	// ClusterRoleBinding specifies the cluster-wide role binding for the user
	ClusterRoleBinding string `json:"clusterrolebinding,omitempty"`
	// RoleBindings specifies the role bindings for the user in specific namespaces
	RoleBindings []RoleBinding `json:"rolebindings,omitempty"`
}

// UserStatus defines the observed state of User.
type UserStatus struct {
	// ServiceAccount is the name of the service account associated with the user
	ServiceAccount string `json:"serviceAccount,omitempty"`
	// LastLoginTime is the time of the user's last login
	LastLoginTime metav1.Time `json:"lastLoginTime,omitempty"`
	// LastUpdatedTime is the time of the last update to the user's information
	LastUpdatedTime metav1.Time `json:"lastUpdatedTime,omitempty"`
	// LastAppliedGeneration is the generation of the last applied configuration
	LastAppliedGeneration int64 `json:"lastAppliedGeneration,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:path=users,scope=Cluster
// +kubebuilder:printcolumn:name="Phone",type="string",JSONPath=".spec.phone"
// +kubebuilder:printcolumn:name="Email",type="string",JSONPath=".spec.email"
// +kubebuilder:printcolumn:name="PlatformRoles",type="string",JSONPath=".spec.platformRoles"
// +kubebuilder:printcolumn:name="State",type=string,JSONPath=`.spec.state`
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`
// User is the Schema for the users API.
type User struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   UserSpec   `json:"spec,omitempty"`
	Status UserStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// UserList contains a list of User.
type UserList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []User `json:"items"`
}

func init() {
	SchemeBuilder.Register(&User{}, &UserList{})
}
