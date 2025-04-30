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

package userbinding

import (
	"context"
	"fmt"
	"time"

	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	userv1beta1 "github.com/kubeants/kubeants-controller/api/user/v1beta1"
	userbindingv1beta1 "github.com/kubeants/kubeants-controller/api/userbinding/v1beta1"
)

// UserBindingReconciler reconciles a UserBinding object
type UserBindingReconciler struct {
	client.Client
	Scheme *runtime.Scheme
}

// 定义标签
const (
	ManagedByLabel   = "kubeants.io/managed-by"
	ManagedByValue   = "userbinding"
	UserBindingLable = "kubeants.io/userbinding"
	UserLabel        = "kubeants.io/user"
)

// +kubebuilder:rbac:groups=userbinding.kubeants.io,resources=userbindings,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=userbinding.kubeants.io,resources=userbindings/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=userbinding.kubeants.io,resources=userbindings/finalizers,verbs=update

// Reconcile is part of the main kubernetes reconciliation loop which aims to
// move the current state of the cluster closer to the desired state.
// TODO(user): Modify the Reconcile function to compare the state specified by
// the UserBinding object against the actual cluster state, and then
// perform operations to make the cluster state reflect the state specified by
// the user.
//
// For more details, check Reconcile and its Result here:
// - https://pkg.go.dev/sigs.k8s.io/controller-runtime@v0.20.2/pkg/reconcile
func (r *UserBindingReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	logger := log.FromContext(ctx).WithValues("userbinding", req.Name)
	start := time.Now()
	logger.Info("✨ Reconciling UserBinding")

	userbinding := &userbindingv1beta1.UserBinding{}
	if err := r.Get(ctx, req.NamespacedName, userbinding); err != nil {
		if errors.IsNotFound(err) {
			logger.Info("✅ UserBinding deleted, nothing to do")
			return ctrl.Result{}, nil
		}
		logger.Error(err, "❌ Failed to fetch UserBinding")
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	// 给自己打标签
	// 检查kubeants.io/managed-by标签
	if err := r.ensureUserBindingLabels(ctx, userbinding); err != nil {
		logger.Error(err, "❌ Failed to patch labels")
		return ctrl.Result{}, err
	}

	// --- 同步User状态 ---
	user := &userv1beta1.User{}
	if err := r.Client.Get(ctx, client.ObjectKey{Name: userbinding.Spec.User}, user); err != nil {
		if errors.IsNotFound(err) {
			logger.Info("⚠️ Related User not found, marking revoke", "user", userbinding.Spec.User)
			// // 关联User不存在了，标记回收
			// userbinding.Status.Revoked = true
			// 删除前清理 RBAC
			if err := r.cleanupRBAC(ctx, userbinding); err != nil {
				logger.Error(err, "❌ Failed to cleanup RBAC before deletion")
				return ctrl.Result{}, err
			}

			if err := r.Delete(ctx, userbinding); err != nil {
				logger.Error(err, "❌ Failed to delete UserBinding")
				return ctrl.Result{}, err
			}
			logger.Info("✅ UserBinding deleted successfully due to missing User")
			return ctrl.Result{}, nil
		} else {
			logger.Error(err, "❌ Failed to fetch related User")
			return ctrl.Result{}, err
		}
	} else {
		// User存在，检查状态
		if user.Spec.State == "active" && userbinding.Status.Revoked {
			logger.Info("✅ User is active again, clearing revoked flag")
			userbinding.Status.Revoked = false
			userbinding.Status.LastTransitionMsg = fmt.Sprintf("✅ User %s active, binding re-activated", userbinding.Spec.User)
			_ = r.Status().Update(ctx, userbinding)
		} else if user.Spec.State != "active" && !userbinding.Status.Revoked {
			userbinding.Status.Revoked = true
			userbinding.Status.LastTransitionMsg = fmt.Sprintf("⚠️ User %s is disabled/deleted", userbinding.Spec.User)
			_ = r.Status().Update(ctx, userbinding)
		}
	}

	// --- 处理权限回收 ---
	if userbinding.Status.Revoked {
		logger.Info("🧹 Starting to revoke RBAC", "userbinding", userbinding.Name)
		if err := r.cleanupRBAC(ctx, userbinding); err != nil {
			logger.Error(err, "❌ Failed to cleanup RBAC")
			userbinding.Status.LastTransitionMsg = fmt.Sprintf("❌ Failed to revoke RBAC: %s", err.Error())
			_ = r.Status().Update(ctx, userbinding)
			return ctrl.Result{}, nil
		}

		// 清理成功记录信息
		userbinding.Status.Synced = false // 下次如果User又恢复，要重新下发
		userbinding.Status.LastTransitionMsg = fmt.Sprintf("✅ Successfully revoked RBAC for userbinding %s", userbinding.Name)

		if err := r.Status().Update(ctx, userbinding); err != nil {
			logger.Error(err, "❌ Failed to update revoke complete")
			return ctrl.Result{}, err
		}
		_ = r.Status().Update(ctx, userbinding)
		logger.Info("✅ RBAC revoked successfully")
		return ctrl.Result{}, nil
	}

	// ✅ 判断是否需要下发（只在 Generation 变化时处理）
	if userbinding.Status.LastAppliedGeneration == userbinding.Generation && userbinding.Status.Synced {
		logger.Info("🚫UserBinding未修改，跳过处理", "UserBinding", userbinding.Name)
		return ctrl.Result{}, nil
	}

	// --- 处理RBAC下发 ---

	logger.Info("🚀 Applying RBAC for userbinding", "userbinding", userbinding.Name)
	if err := r.applyRBAC(ctx, userbinding); err != nil {
		logger.Error(err, "❌ Failed to apply RBAC")
		userbinding.Status.LastTransitionMsg = fmt.Sprintf("❌ Failed to apply RBAC: %s", err.Error())
		_ = r.Status().Update(ctx, userbinding)
		return ctrl.Result{}, nil
	}

	// 更新同步状态
	userbinding.Status.Synced = true
	userbinding.Status.LastSyncTime = metav1.Now()
	userbinding.Status.LastAppliedGeneration = userbinding.Generation
	userbinding.Status.LastTransitionMsg = fmt.Sprintf("✅ Successfully applied RBAC for userbinding %s", userbinding.Name)
	_ = r.Status().Update(ctx, userbinding)
	logger.Info("✅ RBAC applied successfully")

	logger.Info("✅ Reconciliation complete", "duration", time.Since(start))
	return ctrl.Result{}, nil
}

// SetupWithManager sets up the controller with the Manager.
func (r *UserBindingReconciler) SetupWithManager(mgr ctrl.Manager) error {
	if err := mgr.GetFieldIndexer().IndexField(context.Background(), &userbindingv1beta1.UserBinding{}, "spec.user", func(o client.Object) []string {
		binding := o.(*userbindingv1beta1.UserBinding)
		return []string{binding.Spec.User}
	}); err != nil {
		return err
	}

	return ctrl.NewControllerManagedBy(mgr).
		For(&userbindingv1beta1.UserBinding{}).
		Named("userbinding-userbinding").
		Watches(
			&userv1beta1.User{}, // 🔥 监听 User 资源
			handler.EnqueueRequestsFromMapFunc(func(ctx context.Context, obj client.Object) []reconcile.Request {
				user, ok := obj.(*userv1beta1.User)
				if !ok {
					return nil
				}
				// 🌟 找到所有跟这个 User 关联的 UserBinding
				return r.enqueueUserBindingsForUser(ctx, user)
			}),
		).
		Complete(r)
}

func (r *UserBindingReconciler) enqueueUserBindingsForUser(ctx context.Context, user *userv1beta1.User) []reconcile.Request {
	var reqs []reconcile.Request

	bindings := &userbindingv1beta1.UserBindingList{}
	if err := r.List(ctx, bindings, client.MatchingFields{"spec.user": user.Name}); err != nil {
		return nil
	}

	for _, binding := range bindings.Items {
		reqs = append(reqs, reconcile.Request{
			NamespacedName: client.ObjectKey{Name: binding.Name},
		})
	}
	return reqs
}

// 清理RBAC资源
func (r *UserBindingReconciler) cleanupRBAC(ctx context.Context, binding *userbindingv1beta1.UserBinding) error {
	logger := log.FromContext(ctx)
	logger.Info("🚀 Prepare to reclaim permissions")

	// 方式一：通过OwnerReference清理【最优推荐，因为是K8s原生关联】
	// 按 OwnerReference 查找 ClusterRoleBinding / RoleBinding
	// crbList := &rbacv1.ClusterRoleBindingList{}
	// if err := r.List(ctx, crbList, client.MatchingFields{"metadata.ownerReferences.uid": string(binding.UID)}); err != nil {
	// 	return err
	// }
	// for _, crb := range crbList.Items {
	// 	logger.Info("Deleting ClusterRoleBinding", "name", crb.Name)
	// 	if err := r.Client.Delete(ctx, &crb); err != nil && !errors.IsNotFound(err) {
	// 		return err
	// 	}
	// }

	// rbList := &rbacv1.RoleBindingList{}
	// if err := r.List(ctx, rbList, client.MatchingFields{"metadata.ownerReferences.uid": string(binding.UID)}); err != nil {
	// 	return err
	// }
	// for _, rb := range rbList.Items {
	// 	logger.Info("Deleting RoleBinding", "name", rb.Name, "namespace", rb.Namespace)
	// 	if err := r.Client.Delete(ctx, &rb); err != nil && !errors.IsNotFound(err) {
	// 		return err
	// 	}
	// }

	// return nil

	// 方式二：通过LabelSelector清理【更灵活，兼容性高一点】
	labelSelector := client.MatchingLabels{
		"kubeants.io/managed-by":  "userbinding",
		"kubeants.io/userbinding": binding.Name,
	}

	// 清理 ClusterRoleBinding
	crbList := &rbacv1.ClusterRoleBindingList{}
	if err := r.List(ctx, crbList, labelSelector); err != nil {
		return err
	}
	for _, crb := range crbList.Items {
		logger.Info("Deleting ClusterRoleBinding", "name", crb.Name)
		if err := r.Client.Delete(ctx, &crb); err != nil && !errors.IsNotFound(err) {
			return err
		}
	}

	// 清理 RoleBinding
	rbList := &rbacv1.RoleBindingList{}
	if err := r.List(ctx, rbList, labelSelector); err != nil {
		return err
	}
	for _, rb := range rbList.Items {
		logger.Info("Deleting RoleBinding", "name", rb.Name, "namespace", rb.Namespace)
		if err := r.Client.Delete(ctx, &rb); err != nil && !errors.IsNotFound(err) {
			return err
		}
	}

	return nil
}

// applyRBAC 下发RoleBinding或ClusterRoleBinding
func (r *UserBindingReconciler) applyRBAC(ctx context.Context, userbinding *userbindingv1beta1.UserBinding) error {
	switch userbinding.Spec.Scope.Kind {
	case "Cluster":
		_, err := r.reconcileClusterrolebinding(ctx, userbinding)
		return err
	case "Workspace":
		// 🌟 根据label获取workspace下的所有namespace，并下发rolebinding到namespace
		// 构建label标签，用于获取workspace下的所有namespace
		selector := client.MatchingLabels{
			"kubeants.io/workspace": userbinding.Spec.Scope.Name,
		}
		namespaceList := &corev1.NamespaceList{}
		if err := r.List(ctx, namespaceList, selector); err != nil {
			return err
		}

		for _, ns := range namespaceList.Items {
			nsName := ns.Name
			if _, err := r.reconcileRolebinding(ctx, userbinding, nsName); err != nil {
				continue // 单个失败不影响继续其他Namespace
			}
		}
		return nil

	case "Namespace":
		_, err := r.reconcileRolebinding(ctx, userbinding, userbinding.Spec.Scope.Name)
		return err

	default:
		return fmt.Errorf("❌ unsupported scope kind: %s", userbinding.Spec.Scope.Kind)
	}
}

// 下发clusterrolebinding
func (r *UserBindingReconciler) reconcileClusterrolebinding(ctx context.Context, userbinding *userbindingv1beta1.UserBinding) (*rbacv1.ClusterRoleBinding, error) {
	logger := log.FromContext(ctx)

	saName := "user-" + userbinding.Spec.User
	saNamespace := "kubeants-system"
	clusterroleName := userbinding.Spec.Role

	// ManagedByLabel   = "kubeants.io/managed-by"
	// ManagedByValue   = "userbinding"
	// UserBindingLable = "kubeants.io/userbinding"
	// UserLabel        = "kubeants.io/user"
	crbObj := &rbacv1.ClusterRoleBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name: "userbinding-" + userbinding.Name,
			Labels: map[string]string{
				ManagedByLabel:   ManagedByValue,
				UserBindingLable: userbinding.Name,
				UserLabel:        userbinding.Spec.User,
			},
		},
		Subjects: []rbacv1.Subject{
			{
				Kind:      "ServiceAccount",
				Name:      saName,
				Namespace: saNamespace,
			},
		},
		RoleRef: rbacv1.RoleRef{
			APIGroup: "rbac.authorization.k8s.io",
			Kind:     "ClusterRole",
			Name:     clusterroleName,
		},
	}

	// 判断clusterrole和serviceaccount是否存在
	// 校验ServiceAccount存在
	sa := &corev1.ServiceAccount{}
	if err := r.Client.Get(ctx, client.ObjectKey{Name: saName, Namespace: saNamespace}, sa); err != nil {
		if errors.IsNotFound(err) {
			logger.Error(err, "❌ serviceaccount not found,Please check your userbinding configuration.")
			// 🌟 重点：定制一条清晰的LastErrorReason
			userbinding.Status.LastTransitionMsg = fmt.Sprintf("MissingServiceAccount: namespace=%s, name=%s", saNamespace, saName)
			userbinding.Status.LastSyncTime = metav1.Now()
			userbinding.Status.LastAppliedGeneration = userbinding.Generation
			// r.updateStatus(ctx, userbinding)
			_ = r.Status().Update(ctx, userbinding)

			return nil, fmt.Errorf("❌ serviceaccount %s/%s not found: %w", saNamespace, saName, err)
		}
		logger.Error(err, "❌ Check if there is a failure in the serviceaccount.")
		return nil, fmt.Errorf("❌ Check if there is a failure in the serviceaccount")
	}
	clusterRole := &rbacv1.ClusterRole{}
	if err := r.Client.Get(ctx, client.ObjectKey{Name: clusterroleName}, clusterRole); err != nil {
		if errors.IsNotFound(err) {
			logger.Error(err, "❌ clusterrole not found,Please check your userbinding configuration.")

			// 🌟 重点：定制一条清晰的LastErrorReason
			userbinding.Status.LastTransitionMsg = fmt.Sprintf("MissingClusterRole: name=%s", clusterroleName)
			userbinding.Status.LastSyncTime = metav1.Now()
			userbinding.Status.LastAppliedGeneration = userbinding.Generation
			_ = r.Status().Update(ctx, userbinding)

			return nil, fmt.Errorf("❌ clusterrole %s not found: %w", clusterroleName, err)
		}
		logger.Error(err, "❌ Check if there is a failure in the clusterrole.")
		return nil, fmt.Errorf("❌ Check if there is a failure in the clusterrole")

	}

	// 创建或更新 clusterrolebinding
	_, err := ctrl.CreateOrUpdate(ctx, r.Client, crbObj, func() error {
		// 强制把Lable、OwnerReference重新设置一次，保证一致性，防止人为手动修改
		crbObj.Labels = map[string]string{
			ManagedByLabel:   ManagedByValue,
			UserBindingLable: userbinding.Name,
			UserLabel:        userbinding.Spec.User,
		}
		// 设置 OwnerReference 确保 UserBinding 删除时 clusterrolebinding 被清理
		if err := ctrl.SetControllerReference(userbinding, crbObj, r.Scheme); err != nil {
			return err
		}
		return nil
	})

	return crbObj, err
}

// 下发rolebinding
func (r *UserBindingReconciler) reconcileRolebinding(ctx context.Context, userbinding *userbindingv1beta1.UserBinding, namespace string) (*rbacv1.RoleBinding, error) {
	logger := log.FromContext(ctx)

	saName := "user-" + userbinding.Spec.User
	saNamespace := "kubeants-system"
	roleName := userbinding.Spec.Role
	rbObj := &rbacv1.RoleBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "userbinding-" + userbinding.Name,
			Namespace: namespace,
			Labels: map[string]string{
				ManagedByLabel:   ManagedByValue,
				UserBindingLable: userbinding.Name,
				UserLabel:        userbinding.Spec.User,
			},
		},
		Subjects: []rbacv1.Subject{
			{
				Kind:      "ServiceAccount",
				Name:      saName,
				Namespace: saNamespace,
			},
		},
		RoleRef: rbacv1.RoleRef{
			APIGroup: "rbac.authorization.k8s.io",
			Kind:     "Role",
			Name:     roleName,
		},
	}

	// 判断role和serviceaccount是否存在
	// 校验ServiceAccount存在
	sa := &corev1.ServiceAccount{}
	if err := r.Client.Get(ctx, client.ObjectKey{Name: saName, Namespace: saNamespace}, sa); err != nil {
		if errors.IsNotFound(err) {
			logger.Error(err, "❌ serviceaccount not found,Please check your userbinding configuration.")
			// 🌟 重点：定制一条清晰的LastErrorReason
			userbinding.Status.LastTransitionMsg = fmt.Sprintf("MissingServiceAccount: namespace=%s, name=%s", saNamespace, saName)
			userbinding.Status.LastSyncTime = metav1.Now()
			userbinding.Status.LastAppliedGeneration = userbinding.Generation
			_ = r.Status().Update(ctx, userbinding)

			return nil, fmt.Errorf("❌ serviceaccount %s/%s not found: %w", saNamespace, saName, err)
		}
		logger.Error(err, "❌ Check if there is a failure in the serviceaccount.")
		return nil, fmt.Errorf("❌ Check if there is a failure in the serviceaccount")
	}
	role := &rbacv1.Role{}
	if err := r.Client.Get(ctx, client.ObjectKey{Name: roleName, Namespace: namespace}, role); err != nil {
		if errors.IsNotFound(err) {
			logger.Error(err, "❌ role not found,Please check your userbinding configuration.")

			// 🌟 重点：定制一条清晰的LastErrorReason
			userbinding.Status.LastTransitionMsg = fmt.Sprintf("MissingRole: namespace=%s, name=%s", namespace, roleName)
			userbinding.Status.LastSyncTime = metav1.Now()
			userbinding.Status.LastAppliedGeneration = userbinding.Generation
			_ = r.Status().Update(ctx, userbinding)

			return nil, fmt.Errorf("❌ rrole %s not found: %w", roleName, err)
		}
		logger.Error(err, "❌ Check if there is a failure in the role.")
		return nil, fmt.Errorf("❌ Check if there is a failure in the role")
	}

	// 创建或更新 clusterrolebinding
	_, err := ctrl.CreateOrUpdate(ctx, r.Client, rbObj, func() error {
		// 强制把Lable、OwnerReference重新设置一次，保证一致性，防止人为手动修改
		rbObj.Labels = map[string]string{
			ManagedByLabel:   ManagedByValue,
			UserBindingLable: userbinding.Name,
			UserLabel:        userbinding.Spec.User,
		}
		// 设置 OwnerReference 确保 UserBinding 删除时 clusterrolebinding 被清理
		if err := ctrl.SetControllerReference(userbinding, rbObj, r.Scheme); err != nil {
			return err
		}
		return nil
	})

	return rbObj, err
}

// 给userbindig添加user相关label
// kubeants.io/managed-by=user	表示这个资源是 user 管理的
// kubeants.io/user=<user名字>	表示这个资源关联的 user
// kubeants.io/workspace=<workspace名字>
func (r *UserBindingReconciler) ensureUserBindingLabels(ctx context.Context, userbinding *userbindingv1beta1.UserBinding) error {
	// 复制原始对象
	origin := userbinding.DeepCopy()

	// 初始化Labels如果为nil
	if userbinding.Labels == nil {
		userbinding.Labels = make(map[string]string)
	}

	// 定义期望的标签值
	expectedManagedBy := "user"
	expectedUser := userbinding.Spec.User
	// expectedKind := userbinding.Spec.Scope.Kind
	scopeName := userbinding.Spec.Scope.Name
	// expectedCluster := userbinding.

	// 检查当前标签是否符合预期
	needUpdate := false

	// 检查kubeants.io/managed-by标签
	if currentManagedBy, exists := userbinding.Labels["kubeants.io/managed-by"]; !exists || currentManagedBy != expectedManagedBy {
		userbinding.Labels["kubeants.io/managed-by"] = expectedManagedBy
		needUpdate = true
	}

	// 检查kubeants.io/user标签
	if currentUser, exists := userbinding.Labels["kubeants.io/user"]; !exists || currentUser != expectedUser {
		userbinding.Labels["kubeants.io/user"] = expectedUser
		needUpdate = true
	}

	// 检查kubeants.io/workspace标签
	if userbinding.Spec.Scope.Kind == "Workspace" {
		if currentWorkspace, exists := userbinding.Labels["kubeants.io/workspace"]; !exists || currentWorkspace != scopeName {
			userbinding.Labels["kubeants.io/kind"] = "workspace"
			userbinding.Labels["kubeants.io/workspace"] = scopeName
			needUpdate = true
		}
	}

	// 检查kubeants.io/cluster标签，集群权限
	if userbinding.Spec.Scope.Kind == "Cluster" {
		if currentCluster, exists := userbinding.Labels["kubeants.io/cluste"]; !exists || currentCluster != scopeName {
			userbinding.Labels["kubeants.io/kind"] = "cluster"
			userbinding.Labels["kubeants.io/cluster"] = scopeName
			needUpdate = true
		}
	}

	//  检查kubeants.io/namespace标签，namespace权限
	if userbinding.Spec.Scope.Kind == "Namespace" {
		if currentCluster, exists := userbinding.Labels["kubeants.io/namespace"]; !exists || currentCluster != scopeName {
			userbinding.Labels["kubeants.io/kind"] = "namespace"
			userbinding.Labels["kubeants.io/namespace"] = scopeName
			needUpdate = true
		}
	}

	// 如果没有需要更新的内容，直接返回
	if !needUpdate {
		return nil
	}

	// 执行Patch操作
	return r.Patch(ctx, userbinding, client.MergeFrom(origin))
}
