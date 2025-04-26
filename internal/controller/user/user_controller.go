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
	"reflect"
	"regexp"
	"time"

	"golang.org/x/crypto/bcrypt"
	corev1 "k8s.io/api/core/v1"
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

// 定义标签
const (
	ManagedByLabel = "kubeants.io/managed-by"
	ManagedByValue = "user"
	UserLable      = "kubeants.io/user"
)

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
	logger := log.FromContext(ctx).WithValues("user", req.NamespacedName.Name)
	start := time.Now()

	logger.Info("🔄 Starting reconciliation")

	user := userv1beta1.User{}
	if err := r.Get(ctx, req.NamespacedName, &user); err != nil {
		if errors.IsNotFound(err) {
			logger.Info("✅ User deleted, nothing to do")
			return ctrl.Result{}, nil
		}
		logger.Error(err, "❌ Failed to fetch User")
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	// // 检查是否有变化，如果没有变化则不下发
	needsReapply := user.Status.LastAppliedGeneration != user.Generation
	if !needsReapply {
		logger.Info("🚫User未修改，跳过处理", "User", user.Name)
		return ctrl.Result{}, nil
	}

	// 🚀 下发ServiceAccount
	sa, err := r.reconcileServiceAccount(ctx, &user)
	if err != nil {
		logger.Error(err, "❌ Failed to apply serviceaccount", "user", user.Name)
		return ctrl.Result{}, err
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
	if _, err := r.updateStatus(ctx, &user, sa.Name); err != nil {
		logger.Error(err, "❌ Failed to update user status", "user", user.Name)
		return ctrl.Result{}, err
	}
	logger.Info("✅ Reconciliation complete", "duration", time.Since(start))
	return ctrl.Result{}, nil

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
func (r *UserReconciler) reconcileServiceAccount(ctx context.Context, user *userv1beta1.User) (*corev1.ServiceAccount, error) {
	logger := log.FromContext(ctx)
	sa := &corev1.ServiceAccount{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "user-" + user.Name, // 唯一名称，如 user-admin
			Namespace: "kubeants-system",   // 指定 SA 的命名空间
			Labels: map[string]string{
				ManagedByLabel: ManagedByValue,
				UserLable:      user.Name,
			},
		},
	}

	// 创建或更新 SA
	op, err := ctrl.CreateOrUpdate(ctx, r.Client, sa, func() error {
		// 强制把Label、OwnerReference重新设置一次，保证一致性，防止人为手动修改
		sa.Labels = map[string]string{
			ManagedByLabel: ManagedByValue,
			UserLable:      user.Name,
		}
		// 设置 OwnerReference 确保 User 删除时 SA 被清理
		if err := ctrl.SetControllerReference(user, sa, r.Scheme); err != nil {
			return err
		}
		return nil
	})

	logger.Info("✅ ServiceAccount reconciled", "operation", op)
	return sa, err
}

// isHashedPassword 检查密码是否已经是 bcrypt 格式
func isHashedPassword(password string) bool {
	bcryptPattern := `^\$2[aby]\$\d{2}\$[./A-Za-z0-9]{53}$`
	matched, _ := regexp.MatchString(bcryptPattern, password)
	return matched
}

// ensurePasswordHashed 确保用户密码已经加密
func (r *UserReconciler) ensurePasswordHashed(ctx context.Context, user *userv1beta1.User) (bool, error) {
	// 如果已经被加密则不处理
	if isHashedPassword(user.Spec.Password) {
		return false, nil
	}
	// 进行加密
	bcryptPassword, err := bcrypt.GenerateFromPassword([]byte(user.Spec.Password), bcrypt.DefaultCost)
	if err != nil {
		return false, err
	}

	// 更新密码字段
	patch := client.MergeFrom(user.DeepCopy())
	user.Spec.Password = string(bcryptPassword)

	if err := r.Patch(ctx, user, patch); err != nil {
		return false, err
	}
	return true, nil
}
