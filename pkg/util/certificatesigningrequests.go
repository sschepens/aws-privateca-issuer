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

package util

import (
	"strings"

	certificatesv1 "k8s.io/api/certificates/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/clock"
)

// Clock is defined as a package var so it can be stubbed out during tests.
var Clock clock.Clock = clock.RealClock{}

func CertificateSigningRequestIsApproved(csr *certificatesv1.CertificateSigningRequest) bool {
	for _, cond := range csr.Status.Conditions {
		if cond.Type == certificatesv1.CertificateApproved {
			return true
		}
	}
	return false
}

func CertificateSigningRequestIsDenied(csr *certificatesv1.CertificateSigningRequest) bool {
	for _, cond := range csr.Status.Conditions {
		if cond.Type == certificatesv1.CertificateDenied {
			return true
		}
	}
	return false
}

func CertificateSigningRequestIsFailed(csr *certificatesv1.CertificateSigningRequest) bool {
	for _, cond := range csr.Status.Conditions {
		if cond.Type == certificatesv1.CertificateFailed {
			return true
		}
	}
	return false
}

func CertificateSigningRequestSetFailed(csr *certificatesv1.CertificateSigningRequest, reason, message string) {
	nowTime := metav1.NewTime(Clock.Now())

	// Since we only ever set this condition once (enforced by the API), we
	// needn't need to check whether the condition is already set.
	csr.Status.Conditions = append(csr.Status.Conditions, certificatesv1.CertificateSigningRequestCondition{
		Type:               certificatesv1.CertificateFailed,
		Status:             corev1.ConditionTrue,
		Reason:             reason,
		Message:            message,
		LastTransitionTime: nowTime,
		LastUpdateTime:     nowTime,
	})
}

type SignerIssuerRef struct {
	Namespace, Name string
	Type, Group     string
}

// SignerIssuerRefFromSignerName will return a SignerIssuerRef from a
// CertificateSigningRequests.Spec.SignerName
func SignerIssuerRefFromSignerName(name string) (SignerIssuerRef, bool) {
	split := strings.Split(name, "/")
	if len(split) != 2 {
		return SignerIssuerRef{}, false
	}

	signerTypeSplit := strings.SplitN(split[0], ".", 2)
	signerNameSplit := strings.Split(split[1], ".")

	if len(signerTypeSplit) < 2 || signerNameSplit[0] == "" {
		return SignerIssuerRef{}, false
	}

	if len(signerNameSplit) == 1 {
		return SignerIssuerRef{
			Namespace: "",
			Name:      signerNameSplit[0],
			Type:      signerTypeSplit[0],
			Group:     signerTypeSplit[1],
		}, true
	}

	// ClusterIssuers do not have Namespaces
	if signerTypeSplit[0] == "awspcaclusterissuers" {
		return SignerIssuerRef{
			Namespace: "",
			Name:      strings.Join(signerNameSplit[0:], "."),
			Type:      signerTypeSplit[0],
			Group:     signerTypeSplit[1],
		}, true
	}

	// Non Cluster Scoped issuers always have Namespaces
	return SignerIssuerRef{
		Namespace: signerNameSplit[0],
		Name:      strings.Join(signerNameSplit[1:], "."),
		Type:      signerTypeSplit[0],
		Group:     signerTypeSplit[1],
	}, true
}

// IssuerKindFromType will return the awspca.cert-manager.io Issuer Kind from a
// resource type name.
func IssuerKindFromType(issuerType string) (string, bool) {
	switch issuerType {
	case "awspcaissuers":
		return "AWSPCAIssuer", true

	case "awspcaclusterissuers":
		return "AWSPCAClusterIssuer", true

	default:
		return "", false
	}
}
