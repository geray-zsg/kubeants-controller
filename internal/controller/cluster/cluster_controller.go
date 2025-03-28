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

package cluster

import (
	"context"

	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"

	clusterv1beta1 "github.com/kubeants/kubeants-controller/api/cluster/v1beta1"
)

// ClusterReconciler reconciles a Cluster object
type ClusterReconciler struct {
	client.Client
	Scheme *runtime.Scheme
}

// +kubebuilder:rbac:groups=cluster.kubeants.io,resources=clusters,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=cluster.kubeants.io,resources=clusters/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=cluster.kubeants.io,resources=clusters/finalizers,verbs=update

// Reconcile is part of the main kubernetes reconciliation loop which aims to
// move the current state of the cluster closer to the desired state.
// TODO(user): Modify the Reconcile function to compare the state specified by
// the Cluster object against the actual cluster state, and then
// perform operations to make the cluster state reflect the state specified by
// the user.
//
// For more details, check Reconcile and its Result here:
// - https://pkg.go.dev/sigs.k8s.io/controller-runtime@v0.20.2/pkg/reconcile
func (r *ClusterReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	logger := log.FromContext(ctx)

	logger.Info("Reconciling [调和Cluster]")
	cluster := &clusterv1beta1.Cluster{}
	if err := r.Get(ctx, req.NamespacedName, cluster); err != nil {
		if errors.IsNotFound(err) {
			logger.Info("Cluster resource not found. Ignoring since object must be deleted[删除cluster]")
			return ctrl.Result{}, nil
		}
		logger.Error(err, "Failed to get cluster")
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	switch cluster.Spec.State {
	case "active":
		// TODO: 创建集群
		logger.Info("active [当前集群处于活跃状态]")
	case "disable":
		// TODO: 删除集群
		logger.Info("disable [当前集群处于禁用状态]")

	default:
		logger.Info("unknown [当前集群处于未知状态]", "参数无效，只能是active或disable")
	}

	logger.Info("cluster[集群信息]", "cluster", cluster)
	return ctrl.Result{}, nil
}

// SetupWithManager sets up the controller with the Manager.
func (r *ClusterReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&clusterv1beta1.Cluster{}).
		Named("cluster-cluster").
		Complete(r)
}
