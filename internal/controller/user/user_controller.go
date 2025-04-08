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

package user

import (
	"context"
	"fmt"
	"reflect"
	"regexp"
	"time"

	"golang.org/x/crypto/bcrypt"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"

	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"

	userv1beta1 "github.com/kubeants/kubeants-controller/api/user/v1beta1"
)

// UserReconciler reconciles a User object
type UserReconciler struct {
	client.Client
	Scheme *runtime.Scheme
}

// +kubebuilder:rbac:groups=user.kubeants.io,resources=users,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=user.kubeants.io,resources=users/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=user.kubeants.io,resources=users/finalizers,verbs=update

// Reconcile is part of the main kubernetes reconciliation loop which aims to
// move the current state of the cluster closer to the desired state.
// TODO(user): Modify the Reconcile function to compare the state specified by
// the User object against the actual cluster state, and then
// perform operations to make the cluster state reflect the state specified by
// the user.
//
// For more details, check Reconcile and its Result here:
// - https://pkg.go.dev/sigs.k8s.io/controller-runtime@v0.20.2/pkg/reconcile
func (r *UserReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	logger := log.FromContext(ctx)
	// logger.Info("Reconciling User[调和]")

	user := userv1beta1.User{}
	if err := r.Get(ctx, req.NamespacedName, &user); err != nil {
		if errors.IsNotFound(err) {
			logger.Info("User not found. Ignoring since it must have been deleted.")
			return ctrl.Result{}, nil
		}
		logger.Error(err, "Failed to get User[获取用户失败]")
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	// 定义资源关联的label
	labels := map[string]string{"user.kubeants.io/user": user.Name}

	// 检查是否有变化，如果没有变化则不下发
	needsReapply := user.Status.LastAppliedGeneration != user.Generation
	if !needsReapply {
		logger.Info("No changes detected. Skipping reconciliation.", "user", user.Name)
		return ctrl.Result{}, nil
	}

	// ✅ 处理 Finalizer 逻辑，确保删除前回收权限
	if user.ObjectMeta.DeletionTimestamp.IsZero() {
		// 如果 User 没有Finalizer，则添加他
		if !containsString(user.Finalizers, "user.kubeants.io/finalizer") {
			user.Finalizers = append(user.Finalizers, "user.kubeants.io/finalizer")
			if err := r.Update(ctx, &user); err != nil {
				return ctrl.Result{}, err
			}
		}
	} else {
		// User 即将被删除，清理资源
		logger.Info("User is being deleted. Cleaning up resources.")
		_, err := r.cleanupResources(ctx, &user, labels)
		if err != nil {
			return ctrl.Result{}, err
		}

		// 移除finalizer
		user.Finalizers = removeString(user.Finalizers, "user.kubeants.io/finalizer")
		if err := r.Update(ctx, &user); err != nil {
			return ctrl.Result{}, err
		}
		return ctrl.Result{}, nil
	}

	// 1.2.用户被禁用，回收权限
	if user.Spec.State != "active" {
		logger.Info("User is being  disabled. Cleaning up resources[回收权限]")
		return r.cleanupResources(ctx, &user, labels)
	}

	// 2.1.处理 ServiceAccount
	sa, err := r.reconcileServiceAccount(ctx, &user, labels)
	if err != nil {
		logger.Error(err, "Failed to reconcile ServiceAccount[处理ServiceAccount失败]")
		return ctrl.Result{}, fmt.Errorf("failed to reconcile ServiceAccount: %w", err)
	}

	// 2.2.处理clusterroles
	if user.Spec.ClusterRoles != nil {
		if _, err := r.reconcileClusterRoles(ctx, &user, sa, labels); err != nil {
			logger.Error(err, "Failed to reconcile ClusterRoles[处理ClusterRoles失败]")
			return ctrl.Result{}, fmt.Errorf("failed to reconcile ClusterRoles: %w", err)
		}
	}
	// 2.3.处理roles
	if user.Spec.Roles != nil {
		if _, err := r.reconcileRoles(ctx, &user, sa, labels); err != nil {
			logger.Error(err, "Failed to reconcile Roles[处理Roles失败]")
			return ctrl.Result{}, fmt.Errorf("failed to reconcile Roles: %w", err)
		}
	}

	// 密码加密
	updated, err := r.ensurePasswordHashed(ctx, &user)
	if err != nil {
		logger.Error(err, "Failed to hash password.")
		return ctrl.Result{}, err
	}
	if updated {
		logger.Info("User password was hashed[密码加密]", "user", user.Name)
	}

	// 5.更新 User 状态
	r.updateStatus(ctx, &user, sa.Name)
	// ✅ 增加 `RequeueAfter` 避免死循环
	return ctrl.Result{RequeueAfter: 5 * time.Second}, nil

}

// SetupWithManager sets up the controller with the Manager.
func (r *UserReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&userv1beta1.User{}).
		Named("kubeants-user").
		Complete(r)
}

// 更新status信息
func (r *UserReconciler) updateStatus(ctx context.Context, user *userv1beta1.User, saName string) (ctrl.Result, error) {
	logger := log.FromContext(ctx)
	logger.Info("Updating User status[更新User状态]", "用户名", user.Name, "user status信息", user.Status)

	updated := user.DeepCopy()
	updated.Status.LastUpdatedTime = metav1.Now()
	updated.Status.ServiceAccount = saName
	updated.Status.LastAppliedGeneration = user.Generation

	if !reflect.DeepEqual(user.Status, updated.Status) {
		patch := client.MergeFrom(user.DeepCopy())
		if err := r.Status().Patch(ctx, updated, patch); err != nil {
			logger.Error(err, "Failed to update User status[更新User状态失败]", "用户名", user.Name)
			return ctrl.Result{}, err
		}
	}
	logger.Info("User status updated[更新User状态成功]", "user name", user.Name, "user status信息", user.Status)

	return ctrl.Result{RequeueAfter: 5 * time.Second}, nil
}

// 动态生成与User关联的serviceaccount，并注入OwnerReference实现级联删除
func (r *UserReconciler) reconcileServiceAccount(ctx context.Context, user *userv1beta1.User, labels map[string]string) (*corev1.ServiceAccount, error) {
	logger := log.FromContext(ctx)
	sa := &corev1.ServiceAccount{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "user-" + user.Name, // 唯一名称，如 user-admin
			Namespace: "default",           // 指定 SA 的命名空间
			Labels:    labels,
		},
	}

	// 创建或更新 SA
	op, err := ctrl.CreateOrUpdate(ctx, r.Client, sa, func() error {
		// 设置 OwnerReference 确保 User 删除时 SA 被清理
		if err := ctrl.SetControllerReference(user, sa, r.Scheme); err != nil {
			return err
		}
		return nil
	})

	logger.Info("✅ ServiceAccount reconciled", "operation", op)
	return sa, err
}

// reconcileClusterRoles 处理 ClusterRoles 生成对应的clusterrolebinding
func (r *UserReconciler) reconcileClusterRoles(ctx context.Context, user *userv1beta1.User, sa *corev1.ServiceAccount, labels map[string]string) (crbs []*rbacv1.ClusterRoleBinding, err error) {
	logger := log.FromContext(ctx)
	// crbList := make([]*rbacv1.ClusterRoleBinding, 0)

	for _, clusterRole := range user.Spec.ClusterRoles {
		// 构建 ClusterRoleBinding 名称
		crbName := fmt.Sprintf("user-%s-%s", clusterRole, user.Name)

		// 构建 ClusterRoleBinding 对象
		crbObj := &rbacv1.ClusterRoleBinding{
			ObjectMeta: metav1.ObjectMeta{
				Name:   crbName,
				Labels: labels,
			},
			Subjects: []rbacv1.Subject{
				{
					Kind:      "ServiceAccount",
					Name:      sa.Name,
					Namespace: sa.Namespace,
				},
			},
			RoleRef: rbacv1.RoleRef{
				APIGroup: "rbac.authorization.k8s.io",
				Kind:     "ClusterRole",
				Name:     clusterRole,
			},
		}
		// 创建或更新 clusterrolebinding
		opResult, err := ctrl.CreateOrUpdate(ctx, r.Client, crbObj, func() error {
			// 设置OwnerReference 确保删除User 是能级联删除ClusterRoleBinding
			if err := ctrl.SetControllerReference(user, crbObj, r.Scheme); err != nil {
				logger.Error(err, "Failed to set controller reference[设置OwnerReference失败]")
				return err
			}
			return nil
		})

		if err != nil {
			logger.Error(err, "Failed to create or update ClusterRoleBinding", "name", crbName)
			return nil, err // 返回错误，终止处理
		}

		// 记录操作结果
		logger.Info("✅ ClusterRoleBinding reconciled", "name", crbName, "operation", opResult)

		// 将创建的 ClusterRoleBinding 添加到结果列表
		crbs = append(crbs, crbObj)

	}

	return crbs, nil
}

// reconcileRoles 处理 Roles ,支持标签
func (r *UserReconciler) reconcileRoles(ctx context.Context, user *userv1beta1.User, sa *corev1.ServiceAccount, labels map[string]string) (rbs []*rbacv1.RoleBinding, err error) {
	logger := log.FromContext(ctx)

	for _, role := range user.Spec.Roles {
		// 1.处理 namespaceSelector 逻辑，获取匹配的 Namespace 列表
		var namespaceList []string

		// 2.处理namespaceList 数组
		if role.Namespaces != nil {
			namespaceList = append(namespaceList, role.Namespaces...)
		}

		// 3.处理 namespaceSelector
		if role.NamespaceSelector != nil && role.NamespaceSelector.MatchLabels != nil {
			matchedNamespaces, err := r.getNamespacesBySelector(ctx, role.NamespaceSelector.MatchLabels) // 获取匹配的Namespace
			if err != nil {
				logger.Error(err, "Failed to get namespaces by selector[根据Selector获取Namespace失败]", "selector", role.NamespaceSelector.MatchLabels)
				return nil, err
			}
			namespaceList = append(namespaceList, matchedNamespaces...)
		}

		// 2.遍历 namespaceList，为每个 Namespace 创建 RoleBinding
		for _, ns := range namespaceList {
			// 构建 RoleBinding 名称
			rbName := fmt.Sprintf("user-%s-%s", role.Name, user.Name)

			// 构建rolebinding 对象
			rbObj := &rbacv1.RoleBinding{
				ObjectMeta: metav1.ObjectMeta{
					Name:      rbName,
					Namespace: ns,
					Labels:    labels,
				},
				Subjects: []rbacv1.Subject{
					{
						Kind:      "ServiceAccount",
						Name:      sa.Name,
						Namespace: sa.Namespace,
					},
				},
				RoleRef: rbacv1.RoleRef{
					APIGroup: "rbac.authorization.k8s.io",
					Kind:     "ClusterRole",
					Name:     role.Name,
				},
			}

			// 创建或更新 rolebinding
			opResult, err := ctrl.CreateOrUpdate(ctx, r.Client, rbObj, func() error {
				// 设置OwnerReference 确保删除User 是能级联删除RoleBinding
				if err := ctrl.SetControllerReference(user, rbObj, r.Scheme); err != nil {
					logger.Error(err, "Failed to set controller reference[设置OwnerReference失败]")
					return err
				}
				return nil
			})

			if err != err {
				logger.Error(err, "Failed to create or update RoleBinding", "name", rbName)
				return nil, err // 返回错误，终止处理
			}

			// 记录操作结果
			logger.Info("✅ RoleBinding reconciled", "name", rbName, "namespace", ns, "operation", opResult)
			// 将创建的 rolebinding 添加到返回结果列表
			rbs = append(rbs, rbObj)
		}

	}
	return rbs, nil
}

// 获取符合 selector 规则的 namespaces
func (r *UserReconciler) getNamespacesBySelector(ctx context.Context, selector map[string]string) ([]string, error) {
	var namespaceList corev1.NamespaceList
	err := r.List(ctx, &namespaceList, client.MatchingLabels(selector))
	if err != nil {
		return nil, err
	}

	var namespaces []string
	for _, ns := range namespaceList.Items {
		namespaces = append(namespaces, ns.Name)
	}

	return namespaces, nil
}

func (r *UserReconciler) cleanupResources(ctx context.Context, user *userv1beta1.User, labelMap map[string]string) (ctrl.Result, error) {
	logger := log.FromContext(ctx)
	selector := labels.SelectorFromSet(labels.Set(labelMap))
	var errs []error // 收集所有错误，最后一起返回

	// ✅ 1. 删除匹配标签的 ServiceAccount（所有 Namespace）
	saList := &corev1.ServiceAccountList{}
	if err := r.List(ctx, saList, &client.ListOptions{
		LabelSelector: selector,
		Namespace:     "", // 所有命名空间
	}); err != nil {
		logger.Error(err, "Failed to list ServiceAccount")
		errs = append(errs, err)
	} else {
		for _, sa := range saList.Items {
			if err := r.Delete(ctx, &sa); client.IgnoreNotFound(err) != nil {
				logger.Error(err, "Failed to delete ServiceAccount", "name", sa.Name, "namespace", sa.Namespace)
				errs = append(errs, err)
			} else {
				logger.Info("Deleted ServiceAccount", "name", sa.Name, "namespace", sa.Namespace)
			}
		}
	}

	// ✅ 2. 删除匹配标签的 ClusterRoleBinding
	crbList := &rbacv1.ClusterRoleBindingList{}
	if err := r.List(ctx, crbList, client.MatchingLabels(labelMap)); err != nil {
		logger.Error(err, "Failed to list ClusterRoleBinding")
		errs = append(errs, err)
	} else {
		for _, crb := range crbList.Items {
			if err := r.Delete(ctx, &crb); client.IgnoreNotFound(err) != nil {
				logger.Error(err, "Failed to delete ClusterRoleBinding", "name", crb.Name)
				errs = append(errs, err)
			} else {
				logger.Info("Deleted ClusterRoleBinding", "name", crb.Name)
			}
		}
	}

	// ✅ 3. 删除匹配标签的 RoleBinding（所有涉及到的 Namespace）
	seenNamespaces := map[string]bool{} // 防止重复处理

	for _, role := range user.Spec.Roles {
		var namespaceList []string

		// 指定的 namespaces
		if role.Namespaces != nil {
			namespaceList = append(namespaceList, role.Namespaces...)
		}

		// 匹配 label 的 namespace
		if role.NamespaceSelector != nil && role.NamespaceSelector.MatchLabels != nil {
			matchedNamespaces, err := r.getNamespacesBySelector(ctx, role.NamespaceSelector.MatchLabels)
			if err != nil {
				logger.Error(err, "Failed to get namespaces by selector")
				errs = append(errs, err)
				continue
			}
			namespaceList = append(namespaceList, matchedNamespaces...)
		}

		// 删除每个命名空间中的 RoleBinding
		for _, ns := range namespaceList {
			if seenNamespaces[ns] {
				continue // 已处理
			}
			seenNamespaces[ns] = true

			rbList := &rbacv1.RoleBindingList{}
			if err := r.List(ctx, rbList, &client.ListOptions{
				LabelSelector: selector,
				Namespace:     ns,
			}); err != nil {
				logger.Error(err, "Failed to list RoleBinding", "namespace", ns)
				errs = append(errs, err)
				continue
			}

			for _, rb := range rbList.Items {
				if err := r.Delete(ctx, &rb); client.IgnoreNotFound(err) != nil {
					logger.Error(err, "Failed to delete RoleBinding", "name", rb.Name, "namespace", ns)
					errs = append(errs, err)
				} else {
					logger.Info("Deleted RoleBinding", "name", rb.Name, "namespace", ns)
				}
			}
		}
	}

	// 🔚 总结处理
	if len(errs) > 0 {
		return ctrl.Result{}, fmt.Errorf("failed to cleanup some resources: %v", errs)
	}

	logger.Info("✅ Successfully cleaned up all RBAC resources for User", "user", user.Name)
	return ctrl.Result{}, nil
}

// 检查字符串切片是否包含指定字符串
func containsString(slice []string, target string) bool {
	for _, item := range slice {
		if item == target {
			return true
		}
	}
	return false
}

// 移除字符串切片中的目标字符串（代码中使用的 removeString 实现参考）
func removeString(slice []string, target string) []string {
	newSlice := []string{}
	for _, s := range slice {
		if s != target {
			newSlice = append(newSlice, s)
		}
	}
	return newSlice
}

// isHashedPassword 检查密码是否已经是 bcrypt 格式
func isHashedPassword(password string) bool {
	bcryptPattern := `^\$2[aby]\$\d{2}\$[./A-Za-z0-9]{53}$`
	matched, _ := regexp.MatchString(bcryptPattern, password)
	return matched
}

// ensurePasswordHashed 确保用户密码已经加密
func (r *UserReconciler) ensurePasswordHashed(ctx context.Context, user *userv1beta1.User) (bool, error) {
	logger := log.FromContext(ctx)
	// 如果已经被加密则不处理
	if isHashedPassword(user.Spec.Password) {
		logger.Info("User password is already hashed")
		return false, nil
	}
	// 进行加密
	bcryptPassword, err := bcrypt.GenerateFromPassword([]byte(user.Spec.Password), bcrypt.DefaultCost)
	if err != nil {
		logger.Error(err, "用户密码加密失败", "user", user.Name)
		return false, fmt.Errorf("failed to hash password[bcrypt加密失败]: %w", err)
	}

	// 更新密码字段
	patch := client.MergeFrom(user.DeepCopy())
	user.Spec.Password = string(bcryptPassword)

	if err := r.Patch(ctx, user, patch); err != nil {
		logger.Error(err, "Failed to patch User[bcrypt加密后更新用户数据失败]", "user", user.Name)
		return false, fmt.Errorf("failed to patch user[bcrypt加密后更新用户数据失败]: %w", err)
	}
	return true, nil

}
