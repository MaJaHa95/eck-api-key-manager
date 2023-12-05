/*
Copyright 2023.

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

package controller

import (
	"context"
	"fmt"
	"time"

	"encoding/json"

	"github.com/go-logr/logr"

	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	v1beta1 "github.com/majaha95/eck-api-key-manager/api/v1beta1"

	elasticsearch "github.com/elastic/go-elasticsearch/v8"
	elasticsearch_createapikey "github.com/elastic/go-elasticsearch/v8/typedapi/security/createapikey"
	elasticsearch_types "github.com/elastic/go-elasticsearch/v8/typedapi/types"
)

type ExtraMetadataResource struct {
	Namespace string `json:"namespace"`
	Name      string `json:"name"`
}

type ExtraMetadata struct {
	Resource ExtraMetadataResource `json:"resource"`
}

// ElasticsearchApiKeyReconciler reconciles a ElasticsearchApiKey object
type ElasticsearchApiKeyReconciler struct {
	client.Client

	Scheme *runtime.Scheme
}

const apiKeyFinalizer = "github.com_majaha95_eck-api-key-manager_finalizer"

//+kubebuilder:rbac:groups="",resources=secrets,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups=eck.haugenapplications.com,resources=elasticsearchapikeys,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups=eck.haugenapplications.com,resources=elasticsearchapikeys/status,verbs=get;update;patch
//+kubebuilder:rbac:groups=eck.haugenapplications.com,resources=elasticsearchapikeys/finalizers,verbs=update

func (r *ElasticsearchApiKeyReconciler) ensureApiKeyInvalidated(ctx context.Context, wrapper *ClientWrapper, apiKeyId string, logger logr.Logger) error {
	f := func(esClient *elasticsearch.TypedClient) (interface{}, error) {
		resp, err := esClient.Security.InvalidateApiKey().Ids(apiKeyId).Do(ctx)

		if err != nil {
			return nil, err
		}

		// type Response struct {
		// 	ErrorCount                   int                `json:"error_count"`
		// 	ErrorDetails                 []types.ErrorCause `json:"error_details,omitempty"`
		// 	InvalidatedApiKeys           []string           `json:"invalidated_api_keys"`
		// 	PreviouslyInvalidatedApiKeys []string           `json:"previously_invalidated_api_keys"`
		// }

		if resp.ErrorCount > 0 {
			logger.Info("Tried to delete an API Key, but it didn't exist.")
		}

		return nil, nil
	}

	_, err := RunOrRetryElasticsearchRequest(ctx, wrapper, r, f, logger)

	if err != nil {
		return LogAndReturnError(logger, "Error invalidating api key: %w", "Error", err)
	}

	return nil
}

func createMetadata(apiKey *v1beta1.ElasticsearchApiKey) (map[string]json.RawMessage, error) {
	ret := make(map[string]json.RawMessage)

	provided := apiKey.Spec.Metadata
	if provided != nil {
		for key, value := range provided {
			ret[key] = value
		}
	}

	extra := ExtraMetadata{
		Resource: ExtraMetadataResource{
			Namespace: apiKey.ObjectMeta.Namespace,
			Name:      apiKey.ObjectMeta.Name,
		},
	}

	extraJsonBytes, err := json.Marshal(extra)
	if err != nil {
		return nil, err
	}

	ret["kubernetes_managed_"] = extraJsonBytes

	return ret, nil
}

type ElasticsearchDuration struct {
	time.Duration
}

// MarshalJSON converts the Duration to a JSON string in Elasticsearch format
func (d ElasticsearchDuration) MarshalJSON() ([]byte, error) {
	// Elasticsearch supports durations like "1h", "5m", etc.
	// You might need to adjust the format based on your specific requirements in Elasticsearch
	var durationStr string
	if d.Hours() >= 1 {
		durationStr = fmt.Sprintf("%.0fh", d.Hours())
	} else if d.Minutes() >= 1 {
		durationStr = fmt.Sprintf("%.0fm", d.Minutes())
	} else {
		durationStr = fmt.Sprintf("%.0fs", d.Seconds())
	}

	return json.Marshal(durationStr)
}

func (r *ElasticsearchApiKeyReconciler) createApiKeyOrRetry(ctx context.Context, wrapper *ClientWrapper, apiKey *v1beta1.ElasticsearchApiKey, logger logr.Logger) (*elasticsearch_createapikey.Response, error) {
	name := apiKey.ObjectMeta.Name
	if apiKey.Spec.ApiKeyName != "" {
		name = apiKey.Spec.ApiKeyName
	}

	metadata, err := createMetadata(apiKey)
	if err != nil {
		return nil, LogAndReturnError(logger, "Error creating API Key metadata: %w", "Error", err)
	}

	roleDescriptors := make(map[string]elasticsearch_types.RoleDescriptor)

	for key, customType := range apiKey.Spec.RoleDescriptors {
		roleDescriptors[key] = customType.ToElasticsearchType()
	}

	f := func(esClient *elasticsearch.TypedClient) (*elasticsearch_createapikey.Response, error) {
		return esClient.
			Security.CreateApiKey().
			Name(name).
			RoleDescriptors(roleDescriptors).
			Metadata(metadata).
			Expiration(ElasticsearchDuration{Duration: apiKey.Spec.Duration.Duration}).
			Do(ctx)
	}

	resp, err := RunOrRetryElasticsearchRequest(ctx, wrapper, r, f, logger)

	if err != nil {
		return nil, LogAndReturnError(logger, "Error creating api key: %w", "Error", err)
	}

	return resp, nil
}

func getSecretKey(apiKey *v1beta1.ElasticsearchApiKey) types.NamespacedName {
	return types.NamespacedName{
		Name:      apiKey.Spec.SecretName,
		Namespace: apiKey.ObjectMeta.Namespace,
	}
}

func getTime(unixMillis int64) time.Time {
	// Convert Unix milliseconds to time.Time
	seconds := unixMillis / 1000
	nanoseconds := (unixMillis % 1000) * int64(time.Millisecond)
	epochTime := time.Unix(seconds, nanoseconds)

	return epochTime
}

func (r *ElasticsearchApiKeyReconciler) apiKeyValid(ctx context.Context, wrapper *ClientWrapper, apiKey *v1beta1.ElasticsearchApiKey, logger logr.Logger) (bool, error) {
	esClient, err := wrapper.getElasticsearchClient(ctx, r, false, logger)
	if err != nil {
		return false, err
	}

	resp, err := esClient.Security.GetApiKey().Id(apiKey.Status.ApiKeyId).Do(ctx)

	if err != nil {
		return false, err
	}

	for _, result := range resp.ApiKeys {
		if *result.Invalidated {
			logger.Info("Api Key '%s' is invalidated", "ApiKeyId", result.Id)
			continue
		}

		if time.Now().After(getTime(*result.Expiration)) {
			logger.Info("Api Key '%s' is expired", "ApiKeyId", result.Id)
			continue
		}

		// TODO: This would ideally do an Api Key Update rather than triggering rotation
		// if result.RoleDescriptors != apiKey.Spec.RoleDescriptors {
		// 	continue
		// }

		// TODO: Duration
		// TODO: Metadata

		return true, nil
	}

	return false, nil
}

func (r *ElasticsearchApiKeyReconciler) secretExistsForApiKeyId(ctx context.Context, secretReference types.NamespacedName, apiKeyId string, logger logr.Logger) (bool, error) {
	// Define the Secret object
	secret := &corev1.Secret{}

	// Check if the Secret exists
	if err := r.Get(ctx, secretReference, secret); err != nil {
		if client.IgnoreNotFound(err) != nil {
			logger.Info("Api Key secret was not found")

			return false, nil
		}

		return false, LogAndReturnError(logger, "Error occurred retrieving secret: %w", "Error", err)
	}

	currentKeyIdBytes, ok := secret.Data["id"]
	if !ok {
		logger.Error(nil, "Secret exists, but doesn't define an 'id' field. It might have been created or modified outside of this controller.")
		return false, nil
	}

	currentKeyId := string(currentKeyIdBytes)

	if currentKeyId != apiKeyId {
		logger.Error(nil, "Secret exists, but has a different Api Key Id; do you have two ElasticsearchApiKey resources pointing at the same secret? Expected '%s', but got '%s'", "ExpectedApiKeyId", apiKeyId, "ActualApiKeyId", currentKeyId)
		return false, nil
	}

	return true, nil
}

func (r *ElasticsearchApiKeyReconciler) needsRegeneration(ctx context.Context, wrapper *ClientWrapper, secretReference types.NamespacedName, apiKey *v1beta1.ElasticsearchApiKey, logger logr.Logger) (bool, error) {
	if apiKey.Status.ApiKeyId == "" {
		logger.Info("ApiKeyId is not present in resource status")
		return true, nil
	}

	if apiKey.Status.RenewalTime.Time.Before(time.Now()) {
		logger.Info("Api Key is after renewal time")
		return true, nil
	}

	exists, err := r.secretExistsForApiKeyId(ctx, secretReference, apiKey.Status.ApiKeyId, logger)
	if err != nil {
		return false, err
	}

	if !exists {
		logger.Info("No valid secret exists for the Api Key")
		return true, nil
	}

	// Api Key updated
	//   RoleDescriptors
	// No Api Key defined
	valid, err := r.apiKeyValid(ctx, wrapper, apiKey, logger)
	if err != nil {
		return false, err
	}

	if !valid {
		logger.Info("Api Key is invalid")

		return true, nil
	}

	return false, nil
}

func (r *ElasticsearchApiKeyReconciler) markFailed(ctx context.Context, apiKey *v1beta1.ElasticsearchApiKey, wrapper *ClientWrapper, deleteNextApiKeyId bool, logger logr.Logger) error {

	updatedStatus := false

	if deleteNextApiKeyId && apiKey.Status.NextApiKeyId != "" {
		err := r.ensureApiKeyInvalidated(ctx, wrapper, apiKey.Status.NextApiKeyId, logger)

		if err != nil {
			logger.Error(err, "Error deleting failure protection Api Key. This could mean Api Keys are getting generated and not disposed.")
		} else {
			apiKey.Status.NextApiKeyId = ""
			updatedStatus = true
		}
	}

	updatedStatus = updatedStatus || apiKey.Status.Status != v1beta1.ApiKeyConditionFailed
	apiKey.Status.Status = v1beta1.ApiKeyConditionFailed

	if updatedStatus {
		if err := r.Status().Update(ctx, apiKey); err != nil {
			return LogAndReturnError(logger, "Failed to update Api Key status to failed: %w", "Error", err)
		}
	}

	return nil
}

func (r *ElasticsearchApiKeyReconciler) ensureApiKeySyncedAndUpdateStatus(ctx context.Context, elasticClientWrapper *ClientWrapper, apiKey *v1beta1.ElasticsearchApiKey, logger logr.Logger) error {
	secretReference := getSecretKey(apiKey)

	needsRegeneration, err := r.needsRegeneration(ctx, elasticClientWrapper, secretReference, apiKey, logger)
	if err != nil {
		return err
	}

	if !needsRegeneration {
		return nil
	}

	logger.Info("Api Key needs (re)generation...")

	if apiKey.Status.NextApiKeyId != "" {
		if err := r.ensureApiKeyInvalidated(ctx, elasticClientWrapper, apiKey.Status.NextApiKeyId, logger); err != nil {
			logger.Error(err, "Error deleting failure protection Api Key. This could mean Api Keys are getting generated and not disposed.")
		}
	}

	if apiKey.Spec.Duration.Duration <= apiKey.Spec.RenewBefore.Duration {
		return fmt.Errorf("RenewBefore must not be longer than Duration.")
	}

	resp, err := r.createApiKeyOrRetry(ctx, elasticClientWrapper, apiKey, logger)

	if err != nil {
		return err
	}

	expirationTime := getTime(*resp.Expiration)
	expirationTimeK8s := metav1.NewTime(expirationTime)

	renewalTime := expirationTime.Add(-apiKey.Spec.RenewBefore.Duration)
	renewalTimeK8s := metav1.NewTime(renewalTime)

	// Set NextApiKeyId so that we know to clean it up if there's a panic
	apiKey.Status.NextApiKeyId = resp.Id
	apiKey.Status.Status = v1beta1.ApiKeyConditionIssuing
	if err := r.Status().Update(ctx, apiKey); err != nil {
		innerErr := r.markFailed(ctx, apiKey, elasticClientWrapper, true, logger)
		if innerErr != nil {
			logger.Error(innerErr, "Error marking Api Key resource as failed. We must be having a bad day.")
		}

		return err
	}

	if _, err := r.upsertSecret(ctx, secretReference, resp, logger); err != nil {
		innerErr := r.markFailed(ctx, apiKey, elasticClientWrapper, true, logger)
		if innerErr != nil {
			logger.Error(innerErr, "Error marking Api Key resource as failed. We must be having a bad day.")
		}

		return err
	}

	apiKey.Status.NextApiKeyId = ""
	apiKey.Status.ApiKeyId = resp.Id
	apiKey.Status.Status = v1beta1.ApiKeyConditionReady
	apiKey.Status.NotAfter = &expirationTimeK8s
	apiKey.Status.RenewalTime = &renewalTimeK8s

	if err := r.Status().Update(ctx, apiKey); err != nil {
		logger.Error(err, "Failed to update Api Key status, but the Api Key and Secret are synchronized.")

		innerErr := r.markFailed(ctx, apiKey, elasticClientWrapper, false, logger)
		if innerErr != nil {
			logger.Error(innerErr, "Error marking Api Key resource as failed. We must be having a bad day.")
		}

		return err
	}

	return nil
}

func (r *ElasticsearchApiKeyReconciler) upsertSecret(ctx context.Context, secretReference types.NamespacedName, resp *elasticsearch_createapikey.Response, logger logr.Logger) (bool, error) {
	secret := &corev1.Secret{}
	err := r.Get(ctx, secretReference, secret)

	// If the Secret doesn't exist, create it
	if client.IgnoreNotFound(err) != nil {
		return false, err
	}

	isCreate := false
	if err != nil {
		// Secret does not exist, create a new one
		secret = &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      secretReference.Name,
				Namespace: secretReference.Namespace,
			},
			Data: make(map[string][]byte),
		}
		isCreate = true
	}

	// Convert response fields to []byte and assign to Secret data
	secret.Data["id"] = []byte(resp.Id)
	secret.Data["api_key"] = []byte(resp.ApiKey)
	secret.Data["encoded"] = []byte(resp.Encoded)

	// Create or Update the Secret
	if isCreate {
		if err := r.Create(ctx, secret); err != nil {
			return isCreate, LogAndReturnError(logger, "Failed to create secret '%s': %w", "Secret", secretReference, "Error", err)
		}
		logger.Info("Secret created successfully", "Secret", secretReference)
	} else {
		if err := r.Update(ctx, secret); err != nil {
			return isCreate, LogAndReturnError(logger, "Failed to update secret '%s': %w", "Secret", secretReference, "Error", err)
		}

		logger.Info("Secret updated successfully", "Secret", secretReference)
	}

	return isCreate, nil
}

func (r *ElasticsearchApiKeyReconciler) ensureSecretDeleted(ctx context.Context, apiKey *v1beta1.ElasticsearchApiKey, logger logr.Logger) error {
	secretReference := getSecretKey(apiKey)

	// Define the Secret object to delete
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      secretReference.Name,
			Namespace: secretReference.Namespace,
		},
	}

	// Attempt to delete the Secret
	err := r.Delete(ctx, secret)
	if err != nil {
		if client.IgnoreNotFound(err) != nil {
			// If the error is not 'NotFound', return it
			return LogAndReturnError(logger, "Error deleting Secret '%s': %w", "Secret", secretReference, "Error", err)
		}
		// If the Secret is not found, it's already deleted/not present
		logger.Info("Secret already deleted or not present", "Secret", secretReference)
		return nil
	}

	logger.Info("Secret deleted successfully", "Secret", secretReference)
	return nil
}

// Reconcile is part of the main kubernetes reconciliation loop which aims to
// move the current state of the cluster closer to the desired state.
// TODO(user): Modify the Reconcile function to compare the state specified by
// the ElasticsearchApiKey object against the actual cluster state, and then
// perform operations to make the cluster state reflect the state specified by
// the user.
//
// For more details, check Reconcile and its Result here:
// - https://pkg.go.dev/sigs.k8s.io/controller-runtime@v0.16.3/pkg/reconcile
func (r *ElasticsearchApiKeyReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	logger := log.FromContext(ctx)
	logger.Info("Starting reconciliation", "namespace", req.Namespace, "name", req.Name)

	// Fetch the ApiKey instance
	var apiKey v1beta1.ElasticsearchApiKey
	err := r.Get(ctx, req.NamespacedName, &apiKey)
	if err != nil {
		if apierrors.IsNotFound(err) {
			// Object not found, could have been deleted after reconcile request.
			// Return and don't requeue
			logger.Info("ApiKey resource not found. Ignoring since object must be deleted")
			return ctrl.Result{}, nil
		}
		// Error reading the object - requeue the request.
		return ctrl.Result{}, LogAndReturnError(logger, "Failed to get ApiKey: %w", "Error", err)
	}

	elasticClientWrapper, err := GetClientWrapper(apiKey.Spec.Elasticsearch)
	if err != nil {
		return ctrl.Result{}, err
	}

	// Check if the ApiKey resource is marked to be deleted
	isApiKeyMarkedToBeDeleted := apiKey.GetDeletionTimestamp() != nil
	if isApiKeyMarkedToBeDeleted {
		if !contains(apiKey.GetFinalizers(), apiKeyFinalizer) {
			return ctrl.Result{}, nil
		}

		if err := r.ensureSecretDeleted(ctx, &apiKey, logger); err != nil {
			return ctrl.Result{}, err
		}

		if apiKey.Status.NextApiKeyId != "" {
			if err := r.ensureApiKeyInvalidated(ctx, elasticClientWrapper, apiKey.Status.NextApiKeyId, logger); err != nil {
				return ctrl.Result{}, err
			}
		}

		if apiKey.Status.ApiKeyId != "" {
			if err := r.ensureApiKeyInvalidated(ctx, elasticClientWrapper, apiKey.Status.ApiKeyId, logger); err != nil {
				return ctrl.Result{}, err
			}
		}

		// Remove apiKeyFinalizer. Once all finalizers have been
		// removed, the object will be deleted.
		apiKey.SetFinalizers(remove(apiKey.GetFinalizers(), apiKeyFinalizer))
		err := r.Update(ctx, &apiKey)

		return ctrl.Result{}, err
	} else {
		// The object is not being deleted, so if it does not have our finalizer,
		// then we should add the finalizer and update the object. This is needed
		// to ensure proper cleanup before the object is deleted.
		if !contains(apiKey.GetFinalizers(), apiKeyFinalizer) {
			apiKey.SetFinalizers(append(apiKey.GetFinalizers(), apiKeyFinalizer))
			if err := r.Update(ctx, &apiKey); err != nil {
				return ctrl.Result{}, err
			}
		}
	}

	if err := r.ensureApiKeySyncedAndUpdateStatus(ctx, elasticClientWrapper, &apiKey, logger); err != nil {
		return ctrl.Result{}, err
	}

	return ctrl.Result{
		RequeueAfter: apiKey.Status.RenewalTime.Time.Sub(time.Now()),
	}, nil
}

// SetupWithManager sets up the controller with the Manager.
func (r *ElasticsearchApiKeyReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&v1beta1.ElasticsearchApiKey{}).
		Complete(r)
}
