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
	logger.Info("Reconciling User[调和]")

	user := userv1beta1.User{}
	if err := r.Get(ctx, req.NamespacedName, &user); err != nil {
		if errors.IsNotFound(err) {
			logger.Info("User not found. Ignoring since it must have been deleted.")
			return ctrl.Result{}, nil
		}
		logger.Error(err, "Failed to get User[获取用户失败]")
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

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
		_, err := r.cleanupResources(ctx, &user)
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
		return r.cleanupResources(ctx, &user)
	}

	// 2.处理 ServiceAccount
	sa, err := r.reconcileServiceAccount(ctx, &user)
	if err != nil {
		logger.Error(err, "Failed to reconcile ServiceAccount[处理ServiceAccount失败]")
		return ctrl.Result{}, fmt.Errorf("failed to reconcile ServiceAccount: %w", err)
	}

	// 3.处理 ClusterRoleBinding
	if user.Spec.ClusterRoleBinding != "" {
		if err := r.reconcileClusterRoleBinding(ctx, &user, sa); err != nil {
			logger.Error(err, "Failed to reconcile ClusterRoleBinding[处理ClusterRoleBinding失败]")
			return ctrl.Result{}, fmt.Errorf("failed to reconcile ClusterRoleBinding: %w", err)
		}
	}

	// 4.处理 RoleBindings
	if user.Spec.RoleBindings != nil {
		if err := r.reconcileRoleBindings(ctx, &user, sa); err != nil {
			return ctrl.Result{}, err
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

// SetupWithManager sets up the controller with the Manager.
func (r *UserReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&userv1beta1.User{}).
		Named("kubeants-user").
		Complete(r)
}

// 动态生成与User关联的serviceaccount，并注入OwnerReference实现级联删除
func (r *UserReconciler) reconcileServiceAccount(ctx context.Context, user *userv1beta1.User) (*corev1.ServiceAccount, error) {
	logger := log.FromContext(ctx)
	sa := &corev1.ServiceAccount{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "user-" + user.Name, // 唯一名称，如 user-admin
			Namespace: "default",           // 指定 SA 的命名空间
			Labels:    map[string]string{"owner": user.Name},
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

	logger.Info("ServiceAccount reconciled", "operation", op)
	return sa, err
}

// 根据 spec.clusterrolebinding 字段动态绑定集群级权限：
func (r *UserReconciler) reconcileClusterRoleBinding(ctx context.Context, user *userv1beta1.User, sa *corev1.ServiceAccount) error {
	logger := log.FromContext(ctx)

	// 判断对应的clusterrolebinding是否存在
	crb := &rbacv1.ClusterRoleBinding{}
	err := r.Get(ctx, client.ObjectKey{Name: user.Spec.ClusterRoleBinding}, crb)
	if err != nil {
		if errors.IsNotFound(err) {
			logger.Info("ClusterRoleBinding not found", "clusterrolebinding", user.Spec.ClusterRoleBinding)
			return fmt.Errorf("ClusterRoleBinding %s not found", user.Spec.ClusterRoleBinding)
		}
		return err
	}

	// 检查 `SA` 是否已存在于 `Subjects`
	for _, subject := range crb.Subjects {
		if subject.Kind == "ServiceAccount" && subject.Name == sa.Name && subject.Namespace == sa.Namespace {
			// SA 已经在 ClusterRoleBinding 里，不需要更新
			logger.Info("ServiceAccount already exists in ClusterRoleBinding,not need to update")
			return nil
		}
	}

	// ✅ 追加 `SA` 到 `Subjects`，而不是覆盖
	crb.Subjects = append(crb.Subjects, rbacv1.Subject{
		Kind:      "ServiceAccount",
		Name:      sa.Name,
		Namespace: sa.Namespace,
	})

	// ✅ 更新 `ClusterRoleBinding`
	return r.Update(ctx, crb)
}

// 当 User 被删除时，我们需要从 ClusterRoleBinding.Subjects 中移除 SA
func (r *UserReconciler) removeUserFromClusterRoleBinding(ctx context.Context, user *userv1beta1.User) error {
	logger := log.FromContext(ctx)
	// 检查clusterrolebinding是否存在
	crb := &rbacv1.ClusterRoleBinding{}
	if err := r.Get(ctx, client.ObjectKey{Name: user.Spec.ClusterRoleBinding}, crb); err != nil {
		if errors.IsNotFound(err) {
			logger.Info("ClusterRoleBinding not found")
			return nil
		}
		return err
	}

	// 过滤掉 `User` 绑定的 `SA`
	var updateSubjects []rbacv1.Subject
	for _, subject := range crb.Subjects {
		if !(subject.Kind == "ServiceAccount" && subject.Name == "user-"+user.Name) {
			updateSubjects = append(updateSubjects, subject)
		}
	}

	// 如果 Subjects 为空，则不删除 clusterrolebinding，只清空Subjects
	if len(updateSubjects) == 0 {
		crb.Subjects = nil
	} else {
		crb.Subjects = updateSubjects
	}

	return r.Update(ctx, crb)
}

// 移除 RoleBinding 里的 SA
func (r *UserReconciler) removeUserFromRoleBindings(ctx context.Context, user *userv1beta1.User) error {
	logger := log.FromContext(ctx)

	rbList := &rbacv1.RoleBindingList{}
	if err := r.List(ctx, rbList, client.MatchingLabels{"owner": user.Name}); err != nil {
		return err
	}

	for _, rb := range rbList.Items {
		var updatedSubjects []rbacv1.Subject
		for _, subject := range rb.Subjects {
			if !(subject.Kind == "ServiceAccount" && subject.Name == "user-"+user.Name) {
				updatedSubjects = append(updatedSubjects, subject)
			}
		}

		// 如果 `Subjects` 为空，则清空 `RoleBinding`
		if len(updatedSubjects) == 0 {
			rb.Subjects = nil
		} else {
			rb.Subjects = updatedSubjects
		}

		if err := r.Update(ctx, &rb); err != nil {
			logger.Error(err, "Failed to update RoleBinding", "name", rb.Name, "namespace", rb.Namespace)
			return err
		}
	}

	return nil
}

// 根据用户中的spec.rolebindings字段动态绑定命名空间级权限(支持namesapce标签批量注入)：
func (r *UserReconciler) reconcileRoleBindings(ctx context.Context, user *userv1beta1.User, sa *corev1.ServiceAccount) error {
	logger := log.FromContext(ctx)
	logger.Info("Processing RoleBindings")

	for _, rb := range user.Spec.RoleBindings {
		var namespaces []string

		// 处理 namespaces 数组
		if rb.Namespaces != nil {
			namespaces = append(namespaces, rb.Namespaces...)
		}

		// 处理 namespaceSelector
		if rb.NamespaceSelector != nil && rb.NamespaceSelector.MatchLabels != nil {
			matchedNamespaces, err := r.getNamespacesBySelector(ctx, rb.NamespaceSelector.MatchLabels)
			if err != nil {
				logger.Error(err, "Failed to get namespaces by selector", "selector", rb.NamespaceSelector.MatchLabels)
				return err
			}
			namespaces = append(namespaces, matchedNamespaces...)
		}

		// 遍历所有匹配的 namespace，处理 RoleBinding
		for _, ns := range namespaces {
			rbObj := &rbacv1.RoleBinding{}
			err := r.Get(ctx, client.ObjectKey{Name: rb.Name, Namespace: ns}, rbObj)
			if err != nil {
				if errors.IsNotFound(err) {
					logger.Info("RoleBinding not found, skipping", "name", rb.Name, "namespace", ns)
					continue
				}
				logger.Error(err, "Failed to get RoleBinding", "name", rb.Name, "namespace", ns)
				return err
			}

			// 确保 SA 存在于 RoleBinding 的 Subjects 中
			found := false
			for _, subject := range rbObj.Subjects {
				if subject.Kind == "ServiceAccount" && subject.Name == sa.Name && subject.Namespace == sa.Namespace {
					found = true
					break
				}
			}
			if !found {
				rbObj.Subjects = append(rbObj.Subjects, rbacv1.Subject{
					Kind:      "ServiceAccount",
					Name:      sa.Name,
					Namespace: sa.Namespace,
				})
				if err := r.Update(ctx, rbObj); err != nil {
					return err
				}
			}
		}
	}

	return nil
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

// User被删除或者禁用时回收权限
func (r *UserReconciler) cleanupResources(ctx context.Context, user *userv1beta1.User) (ctrl.Result, error) {
	logger := log.FromContext(ctx)

	// ✅ 先移除 `ClusterRoleBinding` 里的 `SA`
	if err := r.removeUserFromClusterRoleBinding(ctx, user); err != nil {
		logger.Error(err, "Failed to remove SA from ClusterRoleBinding")
		return ctrl.Result{}, err
	}

	// ✅ 先移除 `RoleBinding` 里的 `SA`
	if err := r.removeUserFromRoleBindings(ctx, user); err != nil {
		logger.Error(err, "Failed to remove SA from RoleBindings")
		return ctrl.Result{}, err
	}

	// 删除 ClusterRoleBinding
	crbList := &rbacv1.ClusterRoleBindingList{}
	if err := r.List(ctx, crbList, client.MatchingLabels{"owner": user.Name}); err != nil {
		return ctrl.Result{}, err
	}
	for _, crb := range crbList.Items {
		if err := r.Delete(ctx, &crb); err != nil {
			return ctrl.Result{}, err
		}
	}

	// ✅ 删除 `ServiceAccount` , 当前使用的是硬编码，建议改进成lable删除sa
	sa := &corev1.ServiceAccount{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "user-" + user.Name,
			Namespace: "default",
		},
	}
	if err := r.Delete(ctx, sa); client.IgnoreNotFound(err) != nil {
		return ctrl.Result{}, err
	}
	logger.Info("User cleanup completed.", "User", user.Name)
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
