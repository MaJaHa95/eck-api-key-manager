package controller

import (
	"context"
	"fmt"
	"sync"

	"github.com/go-logr/logr"

	"k8s.io/apimachinery/pkg/types"

	corev1 "k8s.io/api/core/v1"

	v1beta1 "github.com/majaha95/eck-api-key-manager/api/v1beta1"

	elasticsearch "github.com/elastic/go-elasticsearch/v8"
)

type ClientWrapper struct {
	mu sync.Mutex

	elasticsearchClientCache *elasticsearch.TypedClient

	addresses    []string
	caSecretName types.NamespacedName

	username           string
	passwordSecretName types.NamespacedName
}

func (w *ClientWrapper) getElasticsearchClient(ctx context.Context, r *ElasticsearchApiKeyReconciler, reload bool, logger logr.Logger) (*elasticsearch.TypedClient, error) {
	w.mu.Lock()
	defer w.mu.Unlock()

	if reload || w.elasticsearchClientCache == nil {
		// Define the Secret object
		var passwordSecret corev1.Secret
		var caSecret corev1.Secret

		if err := r.Get(ctx, w.caSecretName, &caSecret); err != nil {
			logger.Error(err, "Failed to get CA secret")

			return nil, err
		}

		if err := r.Get(ctx, w.passwordSecretName, &passwordSecret); err != nil {
			logger.Error(err, "Failed to get elastic user secret")

			return nil, err
		}

		cert, ok := caSecret.Data["ca.crt"]
		if !ok {
			return nil, LogAndReturnError(logger, "Failed to get CA from secret: key '%s' not found", "Key", "ca.crt")
		}

		passwordBytes, ok := passwordSecret.Data[w.username]
		if !ok {
			return nil, LogAndReturnError(logger, "Failed to get password from secret: key '%s' not found", "Username", w.username)
		}

		cfg := elasticsearch.Config{
			Addresses: w.addresses,
			Username:  w.username,
			Password:  string(passwordBytes),
			CACert:    cert,
		}

		logger.Info("Creating Elasticsearch client...")

		es, err := elasticsearch.NewTypedClient(cfg)
		if err != nil {
			logger.Error(err, "Failed to create Elasticsearch client")
			return nil, err
		}

		w.elasticsearchClientCache = es
	}

	return w.elasticsearchClientCache, nil
}

type ElasticsearchCall[T any] func(esClient *elasticsearch.TypedClient) (T, error)

func RunOrRetryElasticsearchRequest[T any](ctx context.Context, wrapper *ClientWrapper, r *ElasticsearchApiKeyReconciler, function ElasticsearchCall[T], logger logr.Logger) (T, error) {
	esClient, err := wrapper.getElasticsearchClient(ctx, r, false, logger)
	if err != nil {
		var zero T
		return zero, err
	}

	resp, err := function(esClient)

	if err == nil {
		return resp, nil
	}

	// Try again with a refreshed client
	newClient, err := wrapper.getElasticsearchClient(ctx, r, true, logger)
	if err != nil {
		var zero T
		return zero, err
	}

	return function(newClient)
}

var clientsByHost = map[v1beta1.ElasticsearchReference]*ClientWrapper{}
var clientsMu sync.Mutex

func GetClientWrapper(ref v1beta1.ElasticsearchReference) (*ClientWrapper, error) {
	clientsMu.Lock()
	defer clientsMu.Unlock()

	client, ok := clientsByHost[ref]
	if !ok {
		client = &ClientWrapper{
			username: "elastic",
			passwordSecretName: types.NamespacedName{
				Name:      fmt.Sprintf("%s-es-elastic-user", ref.Eck.Name),
				Namespace: ref.Eck.Namespace,
			},
			caSecretName: types.NamespacedName{
				Name:      fmt.Sprintf("%s-es-http-certs-public", ref.Eck.Name),
				Namespace: ref.Eck.Namespace,
			},
			addresses: []string{
				fmt.Sprintf("https://%s-es-http.%s.svc:9200", ref.Eck.Name, ref.Eck.Namespace),
			},
		}

		clientsByHost[ref] = client
	}

	return client, nil
}
