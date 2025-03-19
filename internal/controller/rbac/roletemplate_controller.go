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
	"fmt"
	"reflect"

	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
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
	// 下发的资源标签
	ManagedByLabel    = "kubeants.io/managed-by"
	RoleTemplateLabel = "kubeants.io/role-template"
	ManagedByValue    = "role-template"
	// 默认模板名为role-template-kubeants（系统自带名称）
	DefaultRoleTemplate = "role-template-kubeants"
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
	logger := log.FromContext(ctx)
	// Fetch the RoleTemplate instance;获取RoleTemplate实例

	logger.Info("Reconciling [调和roletemplate]")
	rt := &rbacv1beta1.RoleTemplate{}
	if err := r.Get(ctx, req.NamespacedName, rt); err != nil {
		if errors.IsNotFound(err) {
			// Object not found, perform cleanup;如果没有找到对象，执行清理操作，清理带有该模板标签的所有角色
			logger.Info("RoleTemplate[角色模板] not found, performing cleanup[清理相关的role]")
			return r.cleanupRoles(ctx, req.Name)
		}
		logger.Error(err, "Failed to get RoleTempllastAppliedGenerationate[角色模板获取失败]")
		return ctrl.Result{}, err
	}

	// 判断是否自动注入
	if !rt.Spec.AutoApply {
		logger.Info("AutoApply is false, skipping[自动注入为false，跳过]", "RoleTemplate", rt.Name)
		return ctrl.Result{}, nil
	}

	// ✅ 新增逻辑：如果 `Namespace` 发生变更（新建），也需要重新执行下发逻辑（roleTemplate是否有变化或者新增namesapce时下发）
	needsReapply := rt.Status.LastAppliedGeneration != rt.Generation || hasNewNamespace(ctx, r, rt)
	if !needsReapply {
		logger.Info("RoleTemplate未修改，且没有新的Namespace，跳过处理", "RoleTemplate", rt.Name)
		return ctrl.Result{}, nil
	}

	// 判断是否有改变：通过metadata.generation 字段会在 Spec 发生变更时自动递增去和status.lastAppliedGeneration判断
	appliedDefaultNamespaces := map[string]bool{}
	appliedCustomNamespaces := map[string]bool{}
	// Process default template if it's the default template；如果默认模板是默认模板，则处理默认角色
	if rt.Name == DefaultRoleTemplate {
		logger.Info("Processing default roles for default template[系统模板role规则下发]", "DefaultRoles规则下发", rt.Name)
		if err := r.processRoles(ctx, rt, rt.Spec.DefaultRoles, appliedDefaultNamespaces, false); err != nil {
			logger.Error(err, "Failed to process default roles for default template[系统模板]")
			return ctrl.Result{}, err
		}
	}
	// Always process custom roles;始终处理自定义角色
	logger.Info("Processing custom roles for template[模板role规则下发]", "CustmtRoles规则下发", rt.Name)
	if err := r.processRoles(ctx, rt, rt.Spec.CustomRoles, appliedCustomNamespaces, true); err != nil {
		logger.Error(err, "Failed to process custom roles for template[CustmtRoles规则下发失败]")
		return ctrl.Result{}, err
	}
	// 在 updateStatus 前增加回收逻辑
	oldDefaultNs := rt.Status.AppliedDefaultRolesNamespace
	oldCustomNs := rt.Status.AppliedCustomRolesNamespace

	// 计算需要回收的 Namespace
	staleDefaultNs := findStaleNamespaces(oldDefaultNs, appliedDefaultNamespaces, rt.Spec.DefaultRoles.ExcludedNamespaces)
	staleCustomNs := findStaleNamespaces(oldCustomNs, appliedCustomNamespaces, rt.Spec.CustomRoles.ExcludedNamespaces)

	// 执行回收
	if err := r.cleanupStaleRoles(ctx, rt, staleDefaultNs); err != nil {
		return ctrl.Result{}, err
	}
	if err := r.cleanupStaleRoles(ctx, rt, staleCustomNs); err != nil {
		return ctrl.Result{}, err
	}
	// 更新status
	r.updateStatus(ctx, rt, appliedDefaultNamespaces, appliedCustomNamespaces)
	return ctrl.Result{}, nil
}

// SetupWithManager sets up the controller with the Manager.
func (r *RoleTemplateReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&rbacv1beta1.RoleTemplate{}).
		Owns(&rbacv1.Role{}). // 调用了控制器构建器的Owns方法，指定了这个控制器“拥有”的资源类型。在这里，它指定了rbacv1.Role类型。这意味着，当RoleTemplate资源发生变 化时，这个控制器将负责处理（或“调和”）所有由该RoleTemplate“拥有”的Role资源。这种关系通常用于表达一种层级或依赖关系，其中一个资源（在这里是RoleTemplate）定义了其他资源（在这里是Role）的配置或行为。
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
		Named("rbac-roletemplate"). // 这里指定了控制器的名称
		Complete(r)
}

// 实现 enqueueMatchingRoleTemplates，找到匹配的 RoleTemplate
func (r *RoleTemplateReconciler) enqueueMatchingRoleTemplates(ctx context.Context, ns *corev1.Namespace) []reconcile.Request {
	logger := log.FromContext(ctx)
	logger.Info("Enqueuing RoleTemplates for Namespace[监听namespace]")
	// 获取所有 RoleTemplate
	var roleTemplates rbacv1beta1.RoleTemplateList
	if err := r.List(ctx, &roleTemplates); err != nil {
		logger.Error(err, "Failed to list RoleTemplates")
		return nil
	}

	var requests []reconcile.Request
	for _, rt := range roleTemplates.Items {
		// 检查新 Namespace 是否符合 RoleTemplate 规则
		if isIncluded(ns.Name, rt.Spec.DefaultRoles.Namespaces) ||
			isIncluded(ns.Name, rt.Spec.CustomRoles.Namespaces) {
			requests = append(requests, reconcile.Request{NamespacedName: types.NamespacedName{Name: rt.Name}})
		}
	}
	return requests
}

/*
这个方法会：

	获取所有匹配 RoleTemplate 规则的 Namespace。
	检查这些 Namespace 是否已经下发 Role（判断 Role 是否存在）。
	如果 Namespace 没有 Role，就返回 true，触发重新下发。
*/
func hasNewNamespace(ctx context.Context, r *RoleTemplateReconciler, rt *rbacv1beta1.RoleTemplate) bool {
	logger := log.FromContext(ctx)

	// 获取 `RoleTemplate` 适用的 `Namespace`
	namespaces, err := r.getApplicableNamespaces(ctx, rt.Spec.DefaultRoles.Namespaces, rt.Spec.DefaultRoles.ExcludedNamespaces)
	if err != nil {
		logger.Error(err, "Failed to list applicable namespaces")
		return false
	}

	// 检查哪些 `Namespace` 还没有被 `RoleTemplate` 处理
	for _, ns := range namespaces {
		// 检查 `Role` 是否已经存在
		roleList := &rbacv1.RoleList{}
		err := r.List(ctx, roleList, client.InNamespace(ns), client.MatchingLabels{RoleTemplateLabel: rt.Name})
		if err != nil {
			logger.Error(err, "Failed to list roles in namespace", "namespace", ns)
			continue
		}
		if len(roleList.Items) == 0 {
			logger.Info("检测到新的Namespace需要下发角色", "namespace", ns)
			return true
		}
	}
	return false
}

// 清理模板同时，删除带有该模板标签的所有角色
func (r *RoleTemplateReconciler) cleanupRoles(ctx context.Context, templateName string) (ctrl.Result, error) {
	logger := log.FromContext(ctx)
	logger.Info("Cleaning up Roles for RoleTemplate", "template", templateName)

	var roleList rbacv1.RoleList
	err := r.List(ctx, &roleList, client.MatchingLabels{
		ManagedByLabel:    ManagedByValue,
		RoleTemplateLabel: templateName,
	})
	if err != nil {
		return ctrl.Result{}, err
	}

	for _, role := range roleList.Items {
		logger.Info("Deleting Role", "role", role.Name, "namespace", role.Namespace)
		if err := r.Delete(ctx, &role); err != nil {
			if errors.IsNotFound(err) {
				continue // Role 已被删除，忽略
			}
			logger.Error(err, "Failed to delete Role", "role", role.Name)
			return ctrl.Result{}, err
		}
	}
	return ctrl.Result{}, nil
}

// 应用role
func (r *RoleTemplateReconciler) processRoles(ctx context.Context, rt *rbacv1beta1.RoleTemplate, defaultOrCustomRoles rbacv1beta1.DefaultOrCustomRoles, appliedNamespaces map[string]bool, isCustom bool) error {
	logger := log.FromContext(ctx)
	logger.Info("Processing roles for RoleTemplate", "template", rt.Name, "isCustom", isCustom)

	// 获取应用角色到哪些namespace
	namespaces, err := r.getApplicableNamespaces(ctx, defaultOrCustomRoles.Namespaces, defaultOrCustomRoles.ExcludedNamespaces)
	if err != nil {
		return err
	}

	for _, role := range defaultOrCustomRoles.Roles {
		for _, ns := range namespaces {
			if err := r.ensureRole(ctx, rt, role, ns, isCustom); err != nil {
				return err
			}
			if err := r.ensureRoleBinding(ctx, rt, role, ns, isCustom); err != nil {
				return err
			}
			appliedNamespaces[ns] = true
		}
	}

	return nil
}

// 获取需要下发的namespace清单
func (r *RoleTemplateReconciler) getApplicableNamespaces(ctx context.Context, included, excluded []string) ([]string, error) {
	logger := log.FromContext(ctx)
	var result []string
	// 如果没有包含的namespace内容则直接返回
	if len(included) == 0 {
		return result, nil
	}
	// 获取集群中所有的命名空间
	allNamespaces := &corev1.NamespaceList{}
	if err := r.Client.List(ctx, allNamespaces); err != nil {
		return nil, err
	}
	// 创建排除的namespace集合
	excludedSet := make(map[string]struct{})
	for _, ns := range excluded {
		excludedSet[ns] = struct{}{}
	}

	// 遍历集群所有namespace，根据包含和排除规则，筛选出需要下发role的namespace
	for _, ns := range allNamespaces.Items {
		nsName := ns.Name
		if isIncluded(nsName, included) && !isExcluded(nsName, excludedSet) { //如果namespace在集群，并且没有在排除列表中，则添加到结果列表中（用于最后需要下发的namespace ）
			result = append(result, nsName)
		}
	}
	logger.Info("Applicable namespaces for RoleTemplate", "template", included, "excluded", excluded, "result", result)
	return result, nil
}

// 检查目标名称是否存在于允许列表（白名单）中
func isIncluded(name string, included []string) bool {
	if len(included) == 0 {
		return false
	}
	for _, pattern := range included {
		if pattern == "*" || pattern == name {
			return true
		}
	}
	return false
}

// 检查目标名称是否存在于排除列表（黑名单）中
func isExcluded(name string, excluded map[string]struct{}) bool {
	_, ok := excluded[name]
	return ok
}

// 下发role到对应的namespace
func (r *RoleTemplateReconciler) ensureRole(ctx context.Context, rt *rbacv1beta1.RoleTemplate, temRole rbacv1beta1.TemplateRole, namespace string, isCustom bool) error {
	logger := log.FromContext(ctx)
	logger.Info("Ensuring Role for RoleTemplate", "模板名称", rt.Name, "roleTemplate status信息", rt.Status)
	var roleName string
	if isCustom {
		roleName = fmt.Sprintf("%s-%s", rt.Name, temRole.Name)
	} else {
		roleName = temRole.Name
	}

	desiredRole := &rbacv1.Role{
		ObjectMeta: metav1.ObjectMeta{
			Name:      roleName,
			Namespace: namespace,
			Labels: map[string]string{
				ManagedByLabel:    ManagedByValue,
				RoleTemplateLabel: rt.Name,
			},
		},
		Rules: temRole.Rules,
	}

	// Set controller reference
	// 	设置OwnerReference：它会在desiredRole对象的ObjectMeta中设置一个OwnerReference字段，指向rt（RoleTemplate）对象。这意味着desiredRole（Role）现在被认为是rt的一个子资源或“拥有者”资源。
	// 	垃圾回收：Kubernetes的垃圾回收机制会检查这些所有权关系。如果一个资源的所有拥有者都被删除了，那么这个资源也会被自动删除。这对于保持集群的整洁和避免孤立的资源非常有用。
	// 	事件和日志关联：在Kubernetes中，事件（Events）和日志（Logs）经常用于调试和监控。设置控制器引用可以帮助将子资源的事件和日志与它们的拥有者（即控制器）关联起来，从而更容易地追踪和理解系统的行为。
	// 	权限和访问控制：在某些情况下，Kubernetes的RBAC（基于角色的访问控制）机制可能会利用这些所有权关系来做出访问决策。
	if err := ctrl.SetControllerReference(rt, desiredRole, r.Scheme); err != nil {
		return err
	}

	existingRole := &rbacv1.Role{}
	err := r.Get(ctx, types.NamespacedName{
		Name:      desiredRole.Name,
		Namespace: namespace,
	}, existingRole)

	if err != nil && errors.IsNotFound(err) {
		return r.Create(ctx, desiredRole)
	} else if err != nil {
		return err
	}

	if !reflect.DeepEqual(existingRole.Rules, desiredRole.Rules) ||
		!reflect.DeepEqual(existingRole.Labels, desiredRole.Labels) {
		existingRole.Rules = desiredRole.Rules
		existingRole.Labels = desiredRole.Labels
		return r.Update(ctx, existingRole)
	}

	return nil
}

// 下发rolebinding到对应的namespace
func (r *RoleTemplateReconciler) ensureRoleBinding(ctx context.Context, rt *rbacv1beta1.RoleTemplate, temRole rbacv1beta1.TemplateRole, namespace string, isCustom bool) error {
	logger := log.FromContext(ctx)
	logger.Info("Ensuring RoleBinding for RoleTemplate", "模板名称", rt.Name, "roleTemplate status信息", rt.Status)
	var roleBindingName string
	if isCustom {
		roleBindingName = fmt.Sprintf("%s-%s", rt.Name, temRole.Name)
	} else {
		roleBindingName = temRole.Name
	}
	desiredRoleBinding := &rbacv1.RoleBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name:      roleBindingName,
			Namespace: namespace,
			Labels: map[string]string{
				ManagedByLabel:    ManagedByValue,
				RoleTemplateLabel: rt.Name,
			},
		},
		RoleRef: rbacv1.RoleRef{
			APIGroup: "rbac.authorization.k8s.io",
			Kind:     "Role",
			Name:     roleBindingName,
		},
	}

	// Set controller reference
	if err := ctrl.SetControllerReference(rt, desiredRoleBinding, r.Scheme); err != nil {
		return err
	}

	existingRoleBinding := &rbacv1.RoleBinding{}
	err := r.Get(ctx, types.NamespacedName{
		Name:      desiredRoleBinding.Name,
		Namespace: namespace,
	}, existingRoleBinding)

	if err != nil && errors.IsNotFound(err) {
		return r.Create(ctx, desiredRoleBinding)
	} else if err != nil {
		return err
	}

	if !reflect.DeepEqual(existingRoleBinding.RoleRef, desiredRoleBinding.RoleRef) ||
		!reflect.DeepEqual(existingRoleBinding.Labels, desiredRoleBinding.Labels) {
		existingRoleBinding.RoleRef = desiredRoleBinding.RoleRef
		existingRoleBinding.Labels = desiredRoleBinding.Labels
		return r.Update(ctx, existingRoleBinding)
	}
	return nil
}

// 更新roleTemplate的status
func (r *RoleTemplateReconciler) updateStatus(ctx context.Context, rt *rbacv1beta1.RoleTemplate, defaultNs, customNs map[string]bool) (ctrl.Result, error) {
	logger := log.FromContext(ctx)
	logger.Info("Updating status for RoleTemplate[更新模板status]", "模板名称", rt.Name, "roleTemplate status信息", rt.Status)

	updated := rt.DeepCopy()
	updated.Status.AppliedDefaultRolesNamespace = keys(defaultNs)
	updated.Status.AppliedCustomRolesNamespace = keys(customNs)
	updated.Status.LastUpdateTime = metav1.Now()
	updated.Status.LastAppliedGeneration = rt.Generation

	if !reflect.DeepEqual(rt.Status, updated.Status) {
		if err := r.Status().Update(ctx, updated); err != nil {
			return ctrl.Result{}, err
		}
	}

	logger.Info("Updating status for RoleTemplate[已更新模板status]", "模板名称", rt.Name, "roleTemplate status信息", rt.Status)
	return ctrl.Result{}, nil
}

func keys(m map[string]bool) []string {
	var result []string
	for k := range m {
		result = append(result, k)
	}
	return result
}

// 用于计算需要回收的旧Namespace：
func findStaleNamespaces(old []string, current map[string]bool, excluded []string) []string {
	currentSet := make(map[string]bool)
	for k := range current {
		currentSet[k] = true
	}
	var stale []string
	for _, ns := range old {
		if !currentSet[ns] { // ✅ 旧的 `Namespace` 不在当前 `Role` 适用的 `Namespace` 里，应该回收
			stale = append(stale, ns)
		}
	}

	// ✅ 确保 `ExcludedNamespaces` 里的 `Namespace` 也加入 `stale`
	for _, ns := range excluded {
		if !currentSet[ns] { // 只添加不在 current 里的，避免重复删除
			stale = append(stale, ns)
		}
	}
	return stale
}

// 新增cleanupStaleRoles方法
// 根据Namespace列表清理过期的Role：
func (r *RoleTemplateReconciler) cleanupStaleRoles(ctx context.Context, rt *rbacv1beta1.RoleTemplate, namespaces []string) error {
	logger := log.FromContext(ctx)

	for _, ns := range namespaces {
		var roles rbacv1.RoleList
		err := r.List(ctx, &roles, client.MatchingLabels{
			ManagedByLabel:    ManagedByValue,
			RoleTemplateLabel: rt.Name,
		}, client.InNamespace(ns))
		if err != nil {
			return err
		}
		for _, role := range roles.Items {
			logger.Info("Deleting stale Role[回收]", "role", role.Name, "namespace", ns)
			if err := r.Delete(ctx, &role); err != nil && !errors.IsNotFound(err) {
				return err
			}
		}
	}
	return nil
}
