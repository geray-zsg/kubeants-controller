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

package rbac

import (
	"context"
	"reflect"
	"time"

	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	// rbacv1beta1 "kubeants.io/apis/rbac/v1beta1"
	rbacv1beta1 "github.com/kubeants/kubeants-controller/api/rbac/v1beta1"
)

// RoleTemplateReconciler reconciles a RoleTemplate object
type RoleTemplateReconciler struct {
	client.Client
	Scheme *runtime.Scheme
}

// 定义标签
const (
	ManagedByLabel    = "kubeants.io/managed-by"
	RoleTemplateLabel = "kubeants.io/role-template"
	ManagedByValue    = "role-template"
)

// +kubebuilder:rbac:groups=rbac.kubeants.io,resources=roletemplates,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=rbac.kubeants.io,resources=roletemplates/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=rbac.kubeants.io,resources=roletemplates/finalizers,verbs=update

// Reconcile is part of the main kubernetes reconciliation loop which aims to
// move the current state of the cluster closer to the desired state.
// TODO(user): Modify the Reconcile function to compare the state specified by
// the RoleTemplate object against the actual cluster state, and then
// perform operations to make the cluster state reflect the state specified by
// the user.
//
// For more details, check Reconcile and its Result here:
// - https://pkg.go.dev/sigs.k8s.io/controller-runtime@v0.20.2/pkg/reconcile
func (r *RoleTemplateReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	logger := log.FromContext(ctx).WithValues("roletemplate", req.NamespacedName.Name)
	start := time.Now()

	logger.Info("🔄 Starting reconciliation")

	rt := &rbacv1beta1.RoleTemplate{}
	if err := r.Get(ctx, req.NamespacedName, rt); err != nil {
		if errors.IsNotFound(err) {
			logger.Info("✅ RoleTemplate deleted, nothing to do")
			return ctrl.Result{}, nil
		}
		logger.Error(err, "❌ Failed to fetch RoleTemplate")
		return ctrl.Result{}, err
	}

	// 🚫 未启用自动下发则跳过
	if !rt.Spec.AutoApply {
		logger.Info("🚫 AutoApply is false, skipping")
		// logger.Info("AutoApply is false, skipping[🚫自动注入为false，跳过]", "RoleTemplate", rt.Name)
		return ctrl.Result{}, nil
	}

	// ✅ 判断是否需要下发（只在 Generation 变化时处理）
	if rt.Status.LastAppliedGeneration == rt.Generation {
		logger.Info("🚫RoleTemplate未修改，跳过处理", "RoleTemplate", rt.Name)
		return ctrl.Result{}, nil
	}

	// ✅ 获取当前应下发的命名空间列表
	namespaces, err := r.getApplicableNamespaces(ctx, rt)
	if err != nil {
		logger.Error(err, "❌ Failed to get applicable namespaces")
		return ctrl.Result{}, err
	}

	// 🚀 下发到所有符合条件的命名空间，并记录下发的ns最后更新到status
	applied := []string{}
	for _, ns := range namespaces {
		// 判断ns是否存在
		if err := r.Get(ctx, types.NamespacedName{Name: ns}, &corev1.Namespace{}); err != nil {
			if errors.IsNotFound(err) {
				logger.Info("❌Namespace not found, skipping", "namespace", ns)
				continue
			}
			logger.Error(err, "❌failed to get namespace", "namespace", ns)
			return ctrl.Result{}, err
		}
		if err := r.applyRole(ctx, rt, ns); err != nil {
			logger.Error(err, "❌ Failed to apply role", "namespace", ns)
			return ctrl.Result{}, err
		}
		applied = append(applied, ns)
	}

	// 🧹 清理已不再需要的 namespace 下的role
	oldSet := make(map[string]struct{})
	for _, ns := range rt.Status.AppliedNamespaces {
		oldSet[ns] = struct{}{}
	}
	newSet := make(map[string]struct{})
	for _, ns := range applied {
		newSet[ns] = struct{}{}
	}
	for ns := range oldSet {
		if _, exists := newSet[ns]; !exists {
			if err := r.cleanupRole(ctx, rt, ns); err != nil {
				logger.Error(err, "❌ Failed to cleanup role", "namespace", ns)
				return ctrl.Result{}, err
			}
			logger.Info("🧹 Cleaned up role", "namespace", ns)
		}
	}
	// 更新 status
	if res, err := r.updateStatus(ctx, rt, applied); err != nil {
		logger.Error(err, "❌ Failed to update status")
		return res, err
	}

	logger.Info("✅ Reconciliation complete", "duration", time.Since(start))
	return ctrl.Result{}, nil
}

// SetupWithManager sets up the controller with the Manager.
func (r *RoleTemplateReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&rbacv1beta1.RoleTemplate{}).
		Owns(&rbacv1.Role{}).
		Watches(
			&corev1.Namespace{}, // 监听 Namespace 变化
			handler.EnqueueRequestsFromMapFunc(func(ctx context.Context, obj client.Object) []reconcile.Request {
				ns, ok := obj.(*corev1.Namespace)
				if !ok {
					return nil
				}
				return r.enqueueMatchingRoleTemplates(ctx, ns)
			}),
		).
		Complete(r)
}

// getApplicableNamespaces 根据 spec.namespaces / namespaceSelector 计算目标 namespace 列表
func (r *RoleTemplateReconciler) getApplicableNamespaces(ctx context.Context, rt *rbacv1beta1.RoleTemplate) ([]string, error) {
	// 获取所有namespace
	var nsList corev1.NamespaceList
	if err := r.List(ctx, &nsList); err != nil {
		return nil, err
	}

	// ✅ 处理 spec.excludedNamespaces
	excluded := make(map[string]struct{})
	for _, ns := range rt.Spec.ExcludedNamespaces {
		excluded[ns] = struct{}{}
	}

	result := []string{}

	// ✅ 优先处理 spec.namespaces
	if len(rt.Spec.Namespaces) > 0 {
		if len(rt.Spec.Namespaces) == 1 && rt.Spec.Namespaces[0] == "*" {
			for _, ns := range nsList.Items {
				if _, skip := excluded[ns.Name]; !skip {
					result = append(result, ns.Name)
				}
			}
		} else {
			for _, name := range rt.Spec.Namespaces {
				if _, skip := excluded[name]; !skip {
					result = append(result, name)
				}
			}
		}
		return result, nil
	}

	// ⚙️ 如果没有 spec.namespaces，再处理 namespaceSelector
	if rt.Spec.NamespaceSelector != nil {
		sel, err := metav1.LabelSelectorAsSelector(rt.Spec.NamespaceSelector)
		if err != nil {
			return nil, err
		}
		for _, ns := range nsList.Items {
			if sel.Matches(labels.Set(ns.Labels)) {
				if _, skip := excluded[ns.Name]; !skip {
					result = append(result, ns.Name)
				}
			}
		}
	}
	return result, nil
}

// 下发role到namespace
func (r *RoleTemplateReconciler) applyRole(ctx context.Context, rt *rbacv1beta1.RoleTemplate, ns string) error {
	// 构建role
	role := &rbacv1.Role{
		ObjectMeta: metav1.ObjectMeta{
			Name:      rt.Name,
			Namespace: ns,
			Labels: map[string]string{
				ManagedByLabel:    ManagedByValue,
				RoleTemplateLabel: rt.Name,
			},
		},
		Rules: rt.Spec.Rules,
	}
	// 设置 OwnerReference 确保 上级资源被清理时，自动回收下发的资源
	if err := ctrl.SetControllerReference(rt, role, r.Scheme); err != nil {
		return err
	}

	existing := &rbacv1.Role{}
	err := r.Get(ctx, types.NamespacedName{Name: role.Name, Namespace: ns}, existing)
	if err != nil && errors.IsNotFound(err) {
		return r.Create(ctx, role)
	} else if err != nil {
		return err
	}
	if !reflect.DeepEqual(existing.Rules, role.Rules) || !reflect.DeepEqual(existing.Labels, role.Labels) {
		existing.Rules = role.Rules
		existing.Labels = role.Labels
		return r.Update(ctx, existing)
	}
	return nil
}

// 用于回收已不再需要的 namespace 下的 role
func (r *RoleTemplateReconciler) cleanupRole(ctx context.Context, rt *rbacv1beta1.RoleTemplate, ns string) error {
	role := &rbacv1.Role{}
	err := r.Get(ctx, types.NamespacedName{Name: rt.Name, Namespace: ns}, role)
	if err != nil {
		return client.IgnoreNotFound(err)
	}
	return r.Delete(ctx, role)
}

// 更新状态
func (r *RoleTemplateReconciler) updateStatus(ctx context.Context, rt *rbacv1beta1.RoleTemplate, appliedNamespaces []string) (ctrl.Result, error) {
	logger := log.FromContext(ctx)
	logger.Info("✅ Updating RoleTemplate status", "name", rt.Name)

	updated := rt.DeepCopy()
	updated.Status.AppliedNamespaces = appliedNamespaces
	updated.Status.LastUpdateTime = metav1.Now()
	updated.Status.LastAppliedGeneration = rt.Generation

	if !reflect.DeepEqual(rt.Status, updated.Status) {
		patch := client.MergeFrom(rt.DeepCopy())
		if err := r.Status().Patch(ctx, updated, patch); err != nil {
			// 🛡️ 优雅处理冲突错误
			if errors.IsConflict(err) {
				logger.Info("✅ Conflict when updating RoleTemplate status, will retry automatically", "name", rt.Name)
				return ctrl.Result{Requeue: true}, nil
			}
			logger.Error(err, "❌ Failed to update RoleTemplate status", "name", rt.Name)
			return ctrl.Result{}, err
		}
	}

	logger.Info("⚙️ RoleTemplate status updated successfully", "name", rt.Name)
	return ctrl.Result{}, nil
}

// 用于监听新的namespace创建时下发role
func (r *RoleTemplateReconciler) enqueueMatchingRoleTemplates(ctx context.Context, ns *corev1.Namespace) []ctrl.Request {
	logger := log.FromContext(ctx)
	logger.Info("🛰️ Namespace changed, checking matching RoleTemplates", "namespace", ns.Name)

	var roleTemplates rbacv1beta1.RoleTemplateList
	if err := r.List(ctx, &roleTemplates); err != nil {
		logger.Error(err, "❌ Failed to list RoleTemplates")
		return nil
	}

	var requests []ctrl.Request
	for _, rt := range roleTemplates.Items {
		// 只处理 autoApply=true 的 RoleTemplate
		if !rt.Spec.AutoApply {
			continue
		}

		if namespaceMatches(&rt, ns) {
			requests = append(requests, ctrl.Request{NamespacedName: types.NamespacedName{Name: rt.Name}})
		}
	}
	return requests
}

func namespaceMatches(rt *rbacv1beta1.RoleTemplate, ns *corev1.Namespace) bool {
	// 优先处理 namespaces 列表
	if len(rt.Spec.Namespaces) > 0 {
		if len(rt.Spec.Namespaces) == 1 && rt.Spec.Namespaces[0] == "*" {
			return true
		}
		for _, name := range rt.Spec.Namespaces {
			if name == ns.Name {
				return true
			}
		}
	}

	// 再处理 namespaceSelector
	if rt.Spec.NamespaceSelector != nil {
		sel, err := metav1.LabelSelectorAsSelector(rt.Spec.NamespaceSelector)
		if err == nil && sel.Matches(labels.Set(ns.Labels)) {
			return true
		}
	}

	return false
}
