/*
  Copyright 2021.
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
	"errors"
	"testing"

	logrtesting "github.com/go-logr/logr/testing"
	cmapi "github.com/jetstack/cert-manager/pkg/apis/certmanager/v1"
	cmgen "github.com/jetstack/cert-manager/test/unit/gen"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	certificatesv1 "k8s.io/api/certificates/v1"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/record"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	issuerapi "github.com/cert-manager/aws-privateca-issuer/pkg/api/v1beta1"
	awspca "github.com/cert-manager/aws-privateca-issuer/pkg/aws"
)

func TestCertificateSigningRequestReconcile(t *testing.T) {
	type testCase struct {
		name                          types.NamespacedName
		objects                       []client.Object
		expectedResult                ctrl.Result
		expectedError                 bool
		expectedFailedConditionStatus v1.ConditionStatus
		expectedReadyConditionReason  string
		expectedCertificate           []byte
		mockProvisioner               createMockProvisioner
	}
	tests := map[string]testCase{
		"success-cluster-issuer": {
			name: types.NamespacedName{Name: "cr1"},
			objects: []client.Object{
				cmgen.CertificateSigningRequest(
					"cr1",
					cmgen.SetCertificateSigningRequestSignerName("awspcaclusterissuers."+issuerapi.GroupVersion.Group+"/clusterissuer1"),
					cmgen.SetCertificateSigningRequestStatusCondition(certificatesv1.CertificateSigningRequestCondition{
						Type:   certificatesv1.CertificateApproved,
						Status: v1.ConditionTrue,
					}),
				),
				&issuerapi.AWSPCAClusterIssuer{
					ObjectMeta: metav1.ObjectMeta{
						Name: "clusterissuer1",
					},
					Spec: issuerapi.AWSPCAIssuerSpec{
						SecretRef: issuerapi.AWSCredentialsSecretReference{
							SecretReference: v1.SecretReference{
								Name: "clusterissuer1-credentials",
							},
						},
						Region: "us-east-1",
						Arn:    "arn:aws:acm-pca:us-east-1:account:certificate-authority/12345678-1234-1234-1234-123456789012",
					},
					Status: issuerapi.AWSPCAIssuerStatus{
						Conditions: []metav1.Condition{
							{
								Type:   issuerapi.ConditionTypeReady,
								Status: metav1.ConditionTrue,
							},
						},
					},
				},
				&v1.Secret{
					ObjectMeta: metav1.ObjectMeta{
						Name: "clusterissuer1-credentials",
					},
					Data: map[string][]byte{
						"AWS_ACCESS_KEY_ID":     []byte("ZXhhbXBsZQ=="),
						"AWS_SECRET_ACCESS_KEY": []byte("ZXhhbXBsZQ=="),
					},
				},
			},
			expectedError:       false,
			expectedCertificate: []byte("cert"),
			mockProvisioner: func() {
				awspca.StoreProvisioner(types.NamespacedName{Name: "clusterissuer1"}, &fakeProvisioner{caCert: []byte("cacert"), cert: []byte("cert")})
			},
		},
		"failure-cluster-issuer-not-ready": {
			name: types.NamespacedName{Name: "cr1"},
			objects: []client.Object{
				cmgen.CertificateSigningRequest(
					"cr1",
					cmgen.SetCertificateSigningRequestSignerName("awspcaclusterissuers."+issuerapi.GroupVersion.Group+"/clusterissuer1"),
					cmgen.SetCertificateSigningRequestStatusCondition(certificatesv1.CertificateSigningRequestCondition{
						Type:   certificatesv1.CertificateApproved,
						Status: v1.ConditionTrue,
					}),
				),
				&issuerapi.AWSPCAClusterIssuer{
					ObjectMeta: metav1.ObjectMeta{
						Name: "clusterissuer1",
					},
					Spec: issuerapi.AWSPCAIssuerSpec{
						SecretRef: issuerapi.AWSCredentialsSecretReference{
							SecretReference: v1.SecretReference{
								Name: "clusterissuer1-credentials",
							},
						},
						Region: "us-east-1",
						Arn:    "arn:aws:acm-pca:us-east-1:account:certificate-authority/12345678-1234-1234-1234-123456789012",
					},
					Status: issuerapi.AWSPCAIssuerStatus{
						Conditions: []metav1.Condition{
							{
								Type:   issuerapi.ConditionTypeReady,
								Status: metav1.ConditionFalse,
							},
						},
					},
				},
				&v1.Secret{
					ObjectMeta: metav1.ObjectMeta{
						Name: "clusterissuer1-credentials",
					},
					Data: map[string][]byte{
						"AWS_ACCESS_KEY_ID":     []byte("ZXhhbXBsZQ=="),
						"AWS_SECRET_ACCESS_KEY": []byte("ZXhhbXBsZQ=="),
					},
				},
			},
			expectedError:                 true,
			expectedFailedConditionStatus: v1.ConditionTrue,
			expectedReadyConditionReason:  "IssuerNotReady",
			mockProvisioner: func() {
				awspca.StoreProvisioner(types.NamespacedName{Name: "clusterissuer1"}, &fakeProvisioner{caCert: []byte("cacert"), cert: []byte("cert")})
			},
		},
		"failure-cluster-issuer-not-found": {
			name: types.NamespacedName{Name: "cr1"},
			objects: []client.Object{
				cmgen.CertificateSigningRequest(
					"cr1",
					cmgen.SetCertificateSigningRequestSignerName("awspcaclusterissuers."+issuerapi.GroupVersion.Group+"/clusterissuer1"),
					cmgen.SetCertificateSigningRequestStatusCondition(certificatesv1.CertificateSigningRequestCondition{
						Type:   certificatesv1.CertificateApproved,
						Status: v1.ConditionTrue,
					}),
				),
				&v1.Secret{
					ObjectMeta: metav1.ObjectMeta{
						Name: "clusterissuer1-credentials",
					},
					Data: map[string][]byte{
						"AWS_ACCESS_KEY_ID":     []byte("ZXhhbXBsZQ=="),
						"AWS_SECRET_ACCESS_KEY": []byte("ZXhhbXBsZQ=="),
					},
				},
			},
			expectedFailedConditionStatus: v1.ConditionTrue,
			expectedReadyConditionReason:  "IssuerNotFound",
			expectedError:                 true,
		},
		"failure-provisioner-not-found": {
			name: types.NamespacedName{Name: "cr1"},
			objects: []client.Object{
				cmgen.CertificateSigningRequest(
					"cr1",
					cmgen.SetCertificateSigningRequestSignerName("awspcaclusterissuers."+issuerapi.GroupVersion.Group+"/clusterissuer2"),
					cmgen.SetCertificateSigningRequestStatusCondition(certificatesv1.CertificateSigningRequestCondition{
						Type:   certificatesv1.CertificateApproved,
						Status: v1.ConditionTrue,
					}),
				),
				&issuerapi.AWSPCAClusterIssuer{
					ObjectMeta: metav1.ObjectMeta{
						Name: "clusterissuer2",
					},
					Spec: issuerapi.AWSPCAIssuerSpec{
						SecretRef: issuerapi.AWSCredentialsSecretReference{
							SecretReference: v1.SecretReference{
								Name: "clusterissuer2-credentials",
							},
						},
						Region: "us-east-1",
						Arn:    "arn:aws:acm-pca:us-east-1:account:certificate-authority/12345678-1234-1234-1234-123456789012",
					},
					Status: issuerapi.AWSPCAIssuerStatus{
						Conditions: []metav1.Condition{
							{
								Type:   issuerapi.ConditionTypeReady,
								Status: metav1.ConditionTrue,
							},
						},
					},
				},
				&v1.Secret{
					ObjectMeta: metav1.ObjectMeta{
						Name: "clusterissuer2-credentials",
					},
					Data: map[string][]byte{
						"AWS_ACCESS_KEY_ID":     []byte("ZXhhbXBsZQ=="),
						"AWS_SECRET_ACCESS_KEY": []byte("ZXhhbXBsZQ=="),
					},
				},
			},
			expectedFailedConditionStatus: v1.ConditionTrue,
			expectedReadyConditionReason:  "ProvisionerNotFound",
			expectedError:                 true,
		},
		"failure-sign-failure": {
			name: types.NamespacedName{Name: "cr1"},
			objects: []client.Object{
				cmgen.CertificateSigningRequest(
					"cr1",
					cmgen.SetCertificateSigningRequestSignerName("awspcaclusterissuers."+issuerapi.GroupVersion.Group+"/clusterissuer1"),
					cmgen.SetCertificateSigningRequestStatusCondition(certificatesv1.CertificateSigningRequestCondition{
						Type:   certificatesv1.CertificateApproved,
						Status: v1.ConditionTrue,
					}),
				),
				&issuerapi.AWSPCAClusterIssuer{
					ObjectMeta: metav1.ObjectMeta{
						Name: "clusterissuer1",
					},
					Spec: issuerapi.AWSPCAIssuerSpec{
						SecretRef: issuerapi.AWSCredentialsSecretReference{
							SecretReference: v1.SecretReference{
								Name: "clusterissuer1-credentials",
							},
						},
						Region: "us-east-1",
						Arn:    "arn:aws:acm-pca:us-east-1:account:certificate-authority/12345678-1234-1234-1234-123456789012",
					},
					Status: issuerapi.AWSPCAIssuerStatus{
						Conditions: []metav1.Condition{
							{
								Type:   issuerapi.ConditionTypeReady,
								Status: metav1.ConditionTrue,
							},
						},
					},
				},
				&v1.Secret{
					ObjectMeta: metav1.ObjectMeta{
						Name: "clusterissuer1-credentials",
					},
					Data: map[string][]byte{
						"AWS_ACCESS_KEY_ID":     []byte("ZXhhbXBsZQ=="),
						"AWS_SECRET_ACCESS_KEY": []byte("ZXhhbXBsZQ=="),
					},
				},
			},
			expectedFailedConditionStatus: v1.ConditionTrue,
			expectedReadyConditionReason:  "ErrorSigning",
			expectedError:                 false,
			mockProvisioner: func() {
				awspca.StoreProvisioner(types.NamespacedName{Name: "clusterissuer1"}, &fakeProvisioner{err: errors.New("Sign Failure")})
			},
		},
	}

	scheme := runtime.NewScheme()
	require.NoError(t, issuerapi.AddToScheme(scheme))
	require.NoError(t, cmapi.AddToScheme(scheme))
	require.NoError(t, v1.AddToScheme(scheme))
	require.NoError(t, certificatesv1.AddToScheme(scheme))

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			fakeClient := fake.NewClientBuilder().
				WithScheme(scheme).
				WithObjects(tc.objects...).
				Build()
			controller := CertificateSigningRequestReconciler{
				Client:   fakeClient,
				Log:      logrtesting.NewTestLogger(t),
				Scheme:   scheme,
				Recorder: record.NewFakeRecorder(10),
			}

			ctx := context.TODO()

			if tc.mockProvisioner != nil {
				tc.mockProvisioner()
			}

			result, err := controller.Reconcile(ctx, reconcile.Request{NamespacedName: tc.name})
			if tc.expectedError && err == nil {
				assert.Fail(t, "Expected an error but got none")
			}
			if !tc.expectedError && err != nil {
				assert.Fail(t, "Not expected an error but got one: "+err.Error())
			}

			assert.Equal(t, tc.expectedResult, result, "Unexpected result")

			var csr certificatesv1.CertificateSigningRequest
			err = fakeClient.Get(ctx, tc.name, &csr)
			require.NoError(t, client.IgnoreNotFound(err), "unexpected error from fake client")
			if err == nil {
				if tc.expectedFailedConditionStatus != "" {
					assertCertificateSigningRequestHasFailedCondition(t, tc.expectedFailedConditionStatus, tc.expectedReadyConditionReason, &csr)
				}
				if tc.expectedCertificate != nil {
					assert.Equal(t, tc.expectedCertificate, csr.Status.Certificate)
				}
			}
		})
	}
}

func assertCertificateSigningRequestHasFailedCondition(t *testing.T, status v1.ConditionStatus, reason string, csr *certificatesv1.CertificateSigningRequest) {
	condition := getCertificateSigningRequestCondition(csr, certificatesv1.CertificateFailed)
	if !assert.NotNil(t, condition, "Failed condition not found") {
		return
	}
	assert.Equal(t, status, condition.Status, "unexpected condition status")
	assert.Equal(t, reason, condition.Reason, "unexpected condition reason")
}

func getCertificateSigningRequestCondition(csr *certificatesv1.CertificateSigningRequest, conditionType certificatesv1.RequestConditionType) *certificatesv1.CertificateSigningRequestCondition {
	for _, cond := range csr.Status.Conditions {
		if cond.Type == conditionType {
			return &cond
		}
	}
	return nil
}
