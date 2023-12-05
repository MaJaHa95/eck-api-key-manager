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

package v1beta1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	elasticsearch_types "github.com/elastic/go-elasticsearch/v8/typedapi/types"
)

type ElasticsearchEckReference struct {
	Name      string `json:"name"`
	Namespace string `json:"namespace"`
}

type ElasticsearchReference struct {
	Eck ElasticsearchEckReference `json:"eck"`
}

// ElasticsearchApiKeySpec defines the desired state of ElasticsearchApiKey
type ElasticsearchApiKeySpec struct {
	Duration    *metav1.Duration `json:"duration,omitempty"`
	RenewBefore *metav1.Duration `json:"renewBefore,omitempty"`

	Elasticsearch ElasticsearchReference `json:"elasticsearch"`

	SecretName string `json:"secretName"`

	ApiKeyName      string                          `json:"apiKeyName,omitempty"`
	RoleDescriptors map[string]CustomRoleDescriptor `json:"roleDescriptors"`
	Metadata        elasticsearch_types.Metadata    `json:"metadata,omitempty"`
}

// CertificateConditionType represents an Certificate condition value.
type ApiKeyConditionType string

const (
	ApiKeyConditionReady   ApiKeyConditionType = "Ready"
	ApiKeyConditionIssuing ApiKeyConditionType = "Issuing"
	ApiKeyConditionFailed  ApiKeyConditionType = "Failed"
)

// ElasticsearchApiKeyStatus defines the observed state of ElasticsearchApiKey
type ElasticsearchApiKeyStatus struct {
	// Type of the condition, known values are (`Ready`, `Failed`).
	Status       ApiKeyConditionType `json:"status"`
	ApiKeyId     string              `json:"apiKeyId,omitempty"`
	NextApiKeyId string              `json:"nextApiKeyId,omitempty"`

	NotAfter    *metav1.Time `json:"notAfter,omitempty"`
	RenewalTime *metav1.Time `json:"renewalTime,omitempty"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
//+kubebuilder:subresource:status

// ElasticsearchApiKey is the Schema for the elasticsearchapikeys API
type ElasticsearchApiKey struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   ElasticsearchApiKeySpec   `json:"spec,omitempty"`
	Status ElasticsearchApiKeyStatus `json:"status,omitempty"`
}

//+kubebuilder:object:root=true

// ElasticsearchApiKeyList contains a list of ElasticsearchApiKey
type ElasticsearchApiKeyList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []ElasticsearchApiKey `json:"items"`
}

func init() {
	SchemeBuilder.Register(&ElasticsearchApiKey{}, &ElasticsearchApiKeyList{})
}
