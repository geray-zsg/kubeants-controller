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

package workspace

import (
	"context"
	"fmt"

	corev1 "k8s.io/api/core/v1"

	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"

	"github.com/kubeants/kubeants-controller/api/workspace/v1beta1"
)

// WorkspaceReconciler reconciles a Workspace object
type WorkspaceReconciler struct {
	client.Client
	Scheme *runtime.Scheme
}

// +kubebuilder:rbac:groups=workspace.kubeants.io,resources=workspaces,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=workspace.kubeants.io,resources=workspaces/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=workspace.kubeants.io,resources=workspaces/finalizers,verbs=update

// Reconcile is part of the main kubernetes reconciliation loop which aims to
// move the current state of the cluster closer to the desired state.
// TODO(user): Modify the Reconcile function to compare the state specified by
// the Workspace object against the actual cluster state, and then
// perform operations to make the cluster state reflect the state specified by
// the user.
//
// For more details, check Reconcile and its Result here:
// - https://pkg.go.dev/sigs.k8s.io/controller-runtime@v0.20.2/pkg/reconcile
func (r *WorkspaceReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	logger := log.FromContext(ctx)
	logger.Info("Reconciling [调和workspace]")
	ws := &v1beta1.Workspace{}
	if err := r.Get(ctx, req.NamespacedName, ws); err != nil {
		if errors.IsNotFound(err) {
			logger.Info("Workspace[业务空间] not found")
			return r.removeNsLabels(ctx, req.Name)
		}
		logger.Error(err, "Failed to get Workspace[业务空间]")
	}
	logger.Info("workspace[业务空间]")
	return ctrl.Result{}, nil
}

// SetupWithManager sets up the controller with the Manager.
func (r *WorkspaceReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&v1beta1.Workspace{}).
		Named("workspace-workspace").
		Complete(r)
}

// 删除workspace下相关的namespace
func (r *WorkspaceReconciler) removeNsLabels(ctx context.Context, wsName string) (ctrl.Result, error) {
	logger := log.FromContext(ctx)
	logger.Info("Unbind workspace and namespace tags", "workspace[业务空间]", wsName)

	var nsList corev1.NamespaceList
	if err := r.List(ctx, &nsList, client.MatchingLabels{
		"kubeants.io/workspace":  wsName,
		"kubeants.io/managed-by": "workspace",
	}, client.Limit(100)); err != nil { // 分页查询优化
		return ctrl.Result{}, fmt.Errorf("failed to list namespaces: %w", err)
	}

	// 取消namespace关联的label
	for _, ns := range nsList.Items {
		logger.Info("Removing labels from namespace[解除workspace和namespace关联labels]", "workspace", wsName, "namespace", ns.Name)
		patch := client.MergeFrom(ns.DeepCopy())
		delete(ns.Labels, "kubeants.io/workspace")
		delete(ns.Labels, "kubeants.io/managed-by")

		if err := r.Patch(ctx, &ns, patch); err != nil {
			if errors.IsConflict(err) { // 处理版本冲突
				logger.Info("Retrying due to conflict", "namespace", ns.Name)
				return ctrl.Result{Requeue: true}, nil
			}
			return ctrl.Result{}, err
		}
		logger.Info("Successfully unlinked namespace", "namespace", ns.Name)
	}

	return ctrl.Result{}, nil
}
