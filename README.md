# [Work in Progress!] eck-api-key-manager
CRDs and operator supporting declarative management of Elasticsearch API Keys in Kubernetes, specifically targeting clusters deployed with ECK. Secrets are created and managed in response to `ElasticsearchApiKey` resources in Kubernetes, much like how `cert-manager` exposes certificates.

## Disclaimer
I've wanted something like this for a while, so I decided to be the change I wanted to see in the world. That said, this is my first operator, and worse, I entered without having ever really even touched Go before.

I also don't have it running in production anywhere yet, so my tests have been very minimal.

## Gotchas
* Remember that environment variables don't automatically update when an underlying secret value changes. This operator will not do anything to restart your pod or reset your connection with Elasticsearch. Either make sure your pods will restart after renewal and before expiration, or mount the secret as a volume and write a file watcher to monitor it for changes.
* Updates to role definitions, metadata, and duration do not cause the API Key to be updated. These values _will_ be reflected after the key expires and regenerates, but you might want to delete and recreate the resource if you need it earlier.

## TODO
* Actually test this
* Helm
* Code cleanup
* Learn Go, I guess?
* Docs
* Support resource updates


## Examples
Example resource:

```
apiVersion: eck.haugenapplications.com/v1beta1
kind: ElasticsearchApiKey
metadata:
  name: elasticsearchapikey-sample
spec:
  duration: 10m
  renewBefore: 5m

  elasticsearch:
    eck:
      name: quickstart
      namespace: es-cluster

  secretName: my-api-key

  roleDescriptors:
    viewer: 
      cluster:
      - "all"
      indices: []

```

Creates secret like:

```
apiVersion: v1
items:
- apiVersion: v1
  data:
    api_key: S3BvTFhjV1pUZUNzREtndVNLcDVfZw==
    encoded: TFVWMlRVNDBkMEp1U0ZBME1tNVFUa1UzUlhZNlMzQnZURmhqVjFwVVpVTnpSRXRuZFZOTGNEVmZadz09
    id: LUV2TU40d0JuSFA0Mm5QTkU3RXY=
  kind: Secret
  metadata:
    creationTimestamp: "2023-12-05T02:26:10Z"
    name: my-api-key
    namespace: default
    resourceVersion: "31548"
    uid: 9ed12253-2d27-4b49-a398-67a8fca5e7ce
  type: Opaque
kind: List
metadata:
  resourceVersion: ""
```


## Getting Started

### Prerequisites
- go version v1.20.0+
- docker version 17.03+.
- kubectl version v1.11.3+.
- Access to a Kubernetes v1.11.3+ cluster.

### To Deploy on the cluster
**Build and push your image to the location specified by `IMG`:**

```sh
make docker-build docker-push IMG=<some-registry>/eck-api-key-manager:tag
```

**NOTE:** This image ought to be published in the personal registry you specified. 
And it is required to have access to pull the image from the working environment. 
Make sure you have the proper permission to the registry if the above commands don’t work.

**Install the CRDs into the cluster:**

```sh
make install
```

**Deploy the Manager to the cluster with the image specified by `IMG`:**

```sh
make deploy IMG=<some-registry>/eck-api-key-manager:tag
```

> **NOTE**: If you encounter RBAC errors, you may need to grant yourself cluster-admin 
privileges or be logged in as admin.

**Create instances of your solution**
You can apply the samples (examples) from the config/sample:

```sh
kubectl apply -k config/samples/
```

>**NOTE**: Ensure that the samples has default values to test it out.

### To Uninstall
**Delete the instances (CRs) from the cluster:**

```sh
kubectl delete -k config/samples/
```

**Delete the APIs(CRDs) from the cluster:**

```sh
make uninstall
```

**UnDeploy the controller from the cluster:**

```sh
make undeploy
```

## Contributing
// TODO(user): Add detailed information on how you would like others to contribute to this project

**NOTE:** Run `make --help` for more information on all potential `make` targets

More information can be found via the [Kubebuilder Documentation](https://book.kubebuilder.io/introduction.html)

## License

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

