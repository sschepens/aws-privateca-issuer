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

package aws

import (
	"bytes"
	"context"
	"crypto/md5"
	"encoding/pem"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/middleware"
	"github.com/aws/aws-sdk-go-v2/service/acmpca"
	acmpcatypes "github.com/aws/aws-sdk-go-v2/service/acmpca/types"
	injections "github.com/cert-manager/aws-privateca-issuer/pkg/api/injections"
	"github.com/go-logr/logr"
	cmapi "github.com/jetstack/cert-manager/pkg/apis/certmanager/v1"
	experimentalapi "github.com/jetstack/cert-manager/pkg/apis/experimental/v1alpha1"
	certificatesv1 "k8s.io/api/certificates/v1"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
)

const DEFAULT_DURATION = 30 * 24 * 3600

var collection = new(sync.Map)

// GenericProvisioner abstracts over the Provisioner type for mocking purposes
type GenericProvisioner interface {
	Sign(ctx context.Context, cr *cmapi.CertificateRequest, log logr.Logger) ([]byte, []byte, error)
	SignCSR(ctx context.Context, csr *certificatesv1.CertificateSigningRequest, log logr.Logger) ([]byte, []byte, error)
}

// acmPCAClient abstracts over the methods used from acmpca.Client
type acmPCAClient interface {
	acmpca.GetCertificateAPIClient
	DescribeCertificateAuthority(ctx context.Context, params *acmpca.DescribeCertificateAuthorityInput, optFns ...func(*acmpca.Options)) (*acmpca.DescribeCertificateAuthorityOutput, error)
	IssueCertificate(ctx context.Context, params *acmpca.IssueCertificateInput, optFns ...func(*acmpca.Options)) (*acmpca.IssueCertificateOutput, error)
}

// PCAProvisioner contains logic for issuing PCA certificates
type PCAProvisioner struct {
	pcaClient        acmPCAClient
	arn              string
	signingAlgorithm *acmpcatypes.SigningAlgorithm
	clock            func() time.Time
}

// GetProvisioner gets a provisioner that has previously been stored
func GetProvisioner(name types.NamespacedName) (GenericProvisioner, bool) {
	value, exists := collection.Load(name)
	if !exists {
		return nil, exists
	}

	p, exists := value.(GenericProvisioner)
	return p, exists
}

// StoreProvisioner stores a provisioner in the cache
func StoreProvisioner(name types.NamespacedName, provisioner GenericProvisioner) {
	collection.Store(name, provisioner)
}

// NewProvisioner returns a new PCAProvisioner
func NewProvisioner(config aws.Config, arn string) (p *PCAProvisioner) {
	return &PCAProvisioner{
		pcaClient: acmpca.NewFromConfig(config, acmpca.WithAPIOptions(
			middleware.AddUserAgentKeyValue("aws-privateca-issuer", injections.PlugInVersion),
		)),
		arn: arn,
	}
}

// idempotencyToken is limited to 64 ASCII characters, so make a fixed length hash.
// @see: https://docs.aws.amazon.com/AWSEC2/latest/APIReference/Run_Instance_Idempotency.html
func idempotencyToken(meta *v1.ObjectMeta) string {
	token := []byte(meta.Namespace + "/" + meta.Name)
	return fmt.Sprintf("%x", md5.Sum(token))
}

// Sign takes a certificate request and signs it using PCA
func (p *PCAProvisioner) Sign(ctx context.Context, cr *cmapi.CertificateRequest, log logr.Logger) ([]byte, []byte, error) {
	block, _ := pem.Decode(cr.Spec.Request)
	if block == nil {
		return nil, nil, fmt.Errorf("failed to decode CSR")
	}

	validityExpiration := int64(p.now().Unix()) + DEFAULT_DURATION
	if cr.Spec.Duration != nil {
		validityExpiration = int64(p.now().Unix()) + int64(cr.Spec.Duration.Seconds())
	}

	tempArn := templateArn(p.arn, cr.Spec)

	// Consider it a "retry" if we try to re-create a cert with the same name in the same namespace
	token := idempotencyToken(&cr.ObjectMeta)

	err := getSigningAlgorithm(ctx, p)
	if err != nil {
		return nil, nil, err
	}

	issueParams := acmpca.IssueCertificateInput{
		CertificateAuthorityArn: aws.String(p.arn),
		SigningAlgorithm:        *p.signingAlgorithm,
		TemplateArn:             aws.String(tempArn),
		Csr:                     cr.Spec.Request,
		Validity: &acmpcatypes.Validity{
			Type:  acmpcatypes.ValidityPeriodTypeAbsolute,
			Value: &validityExpiration,
		},
		IdempotencyToken: aws.String(token),
	}

	issueOutput, err := p.pcaClient.IssueCertificate(ctx, &issueParams)

	if err != nil {
		return nil, nil, err
	}

	getParams := acmpca.GetCertificateInput{
		CertificateArn:          aws.String(*issueOutput.CertificateArn),
		CertificateAuthorityArn: aws.String(p.arn),
	}

	log.Info("Created certificate with arn: " + *issueOutput.CertificateArn)

	waiter := acmpca.NewCertificateIssuedWaiter(p.pcaClient)
	err = waiter.Wait(ctx, &getParams, 5*time.Minute)
	if err != nil {
		return nil, nil, err
	}

	getOutput, err := p.pcaClient.GetCertificate(ctx, &getParams)
	if err != nil {
		return nil, nil, err
	}

	certPem := []byte(*getOutput.Certificate + "\n")
	chainPem := []byte(*getOutput.CertificateChain)
	chainIntCAs, rootCA, err := splitRootCACertificate(chainPem)
	if err != nil {
		return nil, nil, err
	}
	certPem = append(certPem, chainIntCAs...)

	return certPem, rootCA, nil
}

// SignCSR takes a certificate signing request and signs it using PCA
func (p *PCAProvisioner) SignCSR(ctx context.Context, csr *certificatesv1.CertificateSigningRequest, log logr.Logger) ([]byte, []byte, error) {
	now := p.now()
	validityExpiration := p.now().Add(DEFAULT_DURATION * time.Second).Unix()
	requestedDuration, ok := csr.Annotations[experimentalapi.CertificateSigningRequestDurationAnnotationKey]
	if ok {
		duration, err := time.ParseDuration(requestedDuration)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to parse requested duration on annotation %q: %w",
				experimentalapi.CertificateSigningRequestDurationAnnotationKey, err)
		}

		validityExpiration = now.Add(duration).Unix()
	}

	tempArn := templateArnCSR(p.arn, csr)

	// Consider it a "retry" if we try to re-create a cert with the same name in the same namespace
	token := idempotencyToken(&csr.ObjectMeta)

	err := getSigningAlgorithm(ctx, p)
	if err != nil {
		return nil, nil, err
	}

	issueParams := acmpca.IssueCertificateInput{
		CertificateAuthorityArn: aws.String(p.arn),
		SigningAlgorithm:        *p.signingAlgorithm,
		TemplateArn:             aws.String(tempArn),
		Csr:                     csr.Spec.Request,
		Validity: &acmpcatypes.Validity{
			Type:  acmpcatypes.ValidityPeriodTypeAbsolute,
			Value: &validityExpiration,
		},
		IdempotencyToken: aws.String(token),
	}

	issueOutput, err := p.pcaClient.IssueCertificate(ctx, &issueParams)

	if err != nil {
		return nil, nil, err
	}

	getParams := acmpca.GetCertificateInput{
		CertificateArn:          aws.String(*issueOutput.CertificateArn),
		CertificateAuthorityArn: aws.String(p.arn),
	}

	log.Info("Created certificate with arn: " + *issueOutput.CertificateArn)

	waiter := acmpca.NewCertificateIssuedWaiter(p.pcaClient)
	err = waiter.Wait(ctx, &getParams, 5*time.Minute)
	if err != nil {
		return nil, nil, err
	}

	getOutput, err := p.pcaClient.GetCertificate(ctx, &getParams)
	if err != nil {
		return nil, nil, err
	}

	certPem := []byte(*getOutput.Certificate + "\n")
	chainPem := []byte(*getOutput.CertificateChain)
	chainIntCAs, rootCA, err := splitRootCACertificate(chainPem)
	if err != nil {
		return nil, nil, err
	}
	certPem = append(certPem, chainIntCAs...)

	return certPem, rootCA, nil
}

func getSigningAlgorithm(ctx context.Context, p *PCAProvisioner) error {
	if p.signingAlgorithm != nil {
		return nil
	}

	describeParams := acmpca.DescribeCertificateAuthorityInput{
		CertificateAuthorityArn: aws.String(p.arn),
	}
	describeOutput, err := p.pcaClient.DescribeCertificateAuthority(ctx, &describeParams)

	if err != nil {
		return err
	}

	p.signingAlgorithm = &describeOutput.CertificateAuthority.CertificateAuthorityConfiguration.SigningAlgorithm
	return nil
}

func (p *PCAProvisioner) now() time.Time {
	if p.clock != nil {
		return p.clock()
	}

	return time.Now()
}

func templateArn(caArn string, spec cmapi.CertificateRequestSpec) string {
	arn := strings.SplitAfterN(caArn, ":", 3)
	prefix := arn[0] + arn[1]

	if spec.IsCA {
		return prefix + "acm-pca:::template/SubordinateCACertificate_PathLen0/V1"
	}

	if len(spec.Usages) == 1 {
		switch spec.Usages[0] {
		case cmapi.UsageCodeSigning:
			return prefix + "acm-pca:::template/CodeSigningCertificate/V1"
		case cmapi.UsageClientAuth:
			return prefix + "acm-pca:::template/EndEntityClientAuthCertificate/V1"
		case cmapi.UsageServerAuth:
			return prefix + "acm-pca:::template/EndEntityServerAuthCertificate/V1"
		case cmapi.UsageOCSPSigning:
			return prefix + "acm-pca:::template/OCSPSigningCertificate/V1"
		}
	} else if len(spec.Usages) == 2 {
		clientServer := (spec.Usages[0] == cmapi.UsageClientAuth && spec.Usages[1] == cmapi.UsageServerAuth)
		serverClient := (spec.Usages[0] == cmapi.UsageServerAuth && spec.Usages[1] == cmapi.UsageClientAuth)
		if clientServer || serverClient {
			return prefix + "acm-pca:::template/EndEntityCertificate/V1"
		}
	}

	return prefix + "acm-pca:::template/BlankEndEntityCertificate_APICSRPassthrough/V1"
}

func templateArnCSR(caArn string, csr *certificatesv1.CertificateSigningRequest) string {
	arn := strings.SplitAfterN(caArn, ":", 3)
	prefix := arn[0] + arn[1]

	isCA := csr.Annotations[experimentalapi.CertificateSigningRequestIsCAAnnotationKey]
	if isCA == "true" {
		return prefix + "acm-pca:::template/SubordinateCACertificate_PathLen0/V1"
	}

	if len(csr.Spec.Usages) == 1 {
		switch csr.Spec.Usages[0] {
		case certificatesv1.UsageCodeSigning:
			return prefix + "acm-pca:::template/CodeSigningCertificate/V1"
		case certificatesv1.UsageClientAuth:
			return prefix + "acm-pca:::template/EndEntityClientAuthCertificate/V1"
		case certificatesv1.UsageServerAuth:
			return prefix + "acm-pca:::template/EndEntityServerAuthCertificate/V1"
		case certificatesv1.UsageOCSPSigning:
			return prefix + "acm-pca:::template/OCSPSigningCertificate/V1"
		}
	} else if len(csr.Spec.Usages) == 2 {
		clientServer := (csr.Spec.Usages[0] == certificatesv1.UsageClientAuth && csr.Spec.Usages[1] == certificatesv1.UsageServerAuth)
		serverClient := (csr.Spec.Usages[0] == certificatesv1.UsageServerAuth && csr.Spec.Usages[1] == certificatesv1.UsageClientAuth)
		if clientServer || serverClient {
			return prefix + "acm-pca:::template/EndEntityCertificate/V1"
		}
	}

	return prefix + "acm-pca:::template/BlankEndEntityCertificate_APICSRPassthrough/V1"
}

func splitRootCACertificate(caCertChainPem []byte) ([]byte, []byte, error) {
	var caChainCerts []byte
	var rootCACert []byte
	for {
		block, rest := pem.Decode(caCertChainPem)
		if block == nil || block.Type != "CERTIFICATE" {
			return nil, nil, fmt.Errorf("failed to read certificate")
		}
		var encBuf bytes.Buffer
		if err := pem.Encode(&encBuf, block); err != nil {
			return nil, nil, err
		}
		if len(rest) > 0 {
			caChainCerts = append(caChainCerts, encBuf.Bytes()...)
			caCertChainPem = rest
		} else {
			rootCACert = append(rootCACert, encBuf.Bytes()...)
			break
		}
	}
	return caChainCerts, rootCACert, nil
}
