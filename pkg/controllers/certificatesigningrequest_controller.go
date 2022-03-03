/*
Copyright 2021 The Kubernetes Authors.

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

package controllers

import (
	"context"
	"fmt"

	"github.com/cert-manager/aws-privateca-issuer/pkg/aws"
	"github.com/cert-manager/aws-privateca-issuer/pkg/util"
	"k8s.io/client-go/tools/record"

	"github.com/go-logr/logr"
	certificatesv1 "k8s.io/api/certificates/v1"
	core "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	authzclient "k8s.io/client-go/kubernetes/typed/authorization/v1"
	"k8s.io/utils/clock"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	api "github.com/cert-manager/aws-privateca-issuer/pkg/api/v1beta1"
)

// CertificateSigningRequestReconciler reconciles a AWSPCAIssuer object
type CertificateSigningRequestReconciler struct {
	client.Client
	SarClient authzclient.SubjectAccessReviewInterface
	Log       logr.Logger
	Scheme    *runtime.Scheme
	Recorder  record.EventRecorder

	Clock clock.Clock
}

// +kubebuilder:rbac:groups=cert-manager.io,resources=certificaterequests,verbs=get;list;watch;update
// +kubebuilder:rbac:groups=cert-manager.io,resources=certificaterequests/status,verbs=get;update;patch
// +kubebuilder:rbac:groups="",resources=secrets,verbs=get;list;watch
// +kubebuilder:rbac:groups="",resources=events,verbs=create;patch

// Reconcile is part of the main kubernetes reconciliation loop which aims to
// move the current state of the cluster closer to the desired state.
//
// For more details, check Reconcile and its Result here:
// - https://pkg.go.dev/sigs.k8s.io/controller-runtime@v0.7.0/pkg/reconcile
func (r *CertificateSigningRequestReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := r.Log.WithValues("certificatesigningrequest", req.NamespacedName)
	csr := new(certificatesv1.CertificateSigningRequest)
	if err := r.Client.Get(ctx, req.NamespacedName, csr); client.IgnoreNotFound(err) != nil {
		log.Error(err, "Error %q getting CSR", err)
		return ctrl.Result{}, err
	}

	if !csr.DeletionTimestamp.IsZero() {
		log.V(4).Info("CSR has been deleted. Ignoring.")
		return ctrl.Result{}, nil
	}

	if util.CertificateSigningRequestIsFailed(csr) {
		log.V(4).Info("Certificate signing request has failed so skipping processing")
		return ctrl.Result{}, nil
	}
	if util.CertificateSigningRequestIsDenied(csr) {
		log.V(4).Info("Certificate signing request has been denied so skipping processing")
		return ctrl.Result{}, nil
	}
	if !util.CertificateSigningRequestIsApproved(csr) {
		r.Recorder.Event(csr, core.EventTypeNormal, "WaitingApproval", "Waiting for the Approved condition before issuing")
		log.V(4).Info("Certificate signing request is not approved so skipping processing")
		return ctrl.Result{}, nil
	}

	if len(csr.Status.Certificate) > 0 {
		log.V(4).Info("certificate field is already set in status so skipping processing")
		return ctrl.Result{}, nil
	}

	ref, ok := util.SignerIssuerRefFromSignerName(csr.Spec.SignerName)
	if !ok {
		log.V(4).Info("Certificate signing request has malformed signer name,", "signerName", csr.Spec.SignerName)
		return ctrl.Result{}, nil
	}

	if ref.Group != api.GroupVersion.Group {
		log.V(4).Info("Certificate signing request signerName group does not match our group so skipping processing")
		return ctrl.Result{}, nil
	}

	kind, ok := util.IssuerKindFromType(ref.Type)
	if !ok {
		log.V(4).Info("Certificate signing request signerName type does not match 'issuers' or 'clusterissuers' so skipping processing")
		return ctrl.Result{}, nil
	}

	if kind == "AWSPCAIssuer" {
		r.Recorder.Eventf(csr, core.EventTypeWarning, "InvalidIssuer", "Only AWSPCAClusterIssuer is currently supported")
		_ = r.setFailed(ctx, csr, "InvalidIssuer", "AWSPCAIssuer is not supported")
		return ctrl.Result{}, nil
	}

	issuerName := types.NamespacedName{
		Namespace: ref.Namespace,
		Name:      ref.Name,
	}
	iss, err := util.GetGenericIssuer(ctx, r.Client, issuerName, kind)
	if err != nil {
		log.Error(err, "Failed to retrieve Issuer resource")
		r.Recorder.Eventf(csr, core.EventTypeWarning, "IssuerNotFound", "Referenced %s %s/%s not found", kind, ref.Namespace, ref.Name)
		_ = r.setFailed(ctx, csr, "IssuerNotFound", "issuer could not be found")
		return ctrl.Result{}, err
	}

	if !isReady(iss) {
		err := fmt.Errorf("issuer %s is not ready", iss.GetName())
		_ = r.setFailed(ctx, csr, "IssuerNotReady", "issuer is not ready")
		return ctrl.Result{}, err
	}

	provisioner, ok := aws.GetProvisioner(issuerName)
	if !ok {
		err := fmt.Errorf("provisioner for %s not found", issuerName)
		log.Error(err, "failed to retrieve provisioner")
		_ = r.setFailed(ctx, csr, "ProvisionerNotFound", "failed to retrieve provisioner: "+err.Error())
		return ctrl.Result{}, err
	}

	pem, _, err := provisioner.SignCSR(ctx, csr, log)
	if err != nil {
		log.Error(err, "failed to request certificate from PCA")
		return ctrl.Result{}, r.setFailed(ctx, csr, "ErrorSigning", "failed to request certificate from PCA: "+err.Error())
	}
	csr.Status.Certificate = pem

	r.Recorder.Event(csr, core.EventTypeWarning, "CertificateIssued", "Certificate self signed successfully")

	return ctrl.Result{}, r.Client.Status().Update(ctx, csr)
}

// SetupWithManager sets up the controller with the Manager.
func (r *CertificateSigningRequestReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&certificatesv1.CertificateSigningRequest{}).
		Complete(r)
}

func (r *CertificateSigningRequestReconciler) setFailed(ctx context.Context, csr *certificatesv1.CertificateSigningRequest, reason, message string, args ...interface{}) error {
	completeMessage := fmt.Sprintf(message, args...)
	util.CertificateSigningRequestSetFailed(csr, reason, completeMessage)

	r.Recorder.Event(csr, core.EventTypeWarning, reason, completeMessage)

	return r.Client.Status().Update(ctx, csr)
}
