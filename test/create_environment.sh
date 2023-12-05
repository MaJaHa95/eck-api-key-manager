# kubectl create -f https://download.elastic.co/downloads/eck/2.10.0/crds.yaml
kubectl apply -f https://download.elastic.co/downloads/eck/2.10.0/operator.yaml

# kubectl create namespace es-cluster

cat <<EOF | kubectl apply -f -
apiVersion: elasticsearch.k8s.elastic.co/v1
kind: Elasticsearch
metadata:
  name: quickstart
  namespace: es-cluster
spec:
  version: 8.11.1
  nodeSets:
  - name: default
    count: 1
    config:
      node.store.allow_mmap: false
EOF

kubectl -n default delete pod curl-es
cat <<EOF | kubectl apply -f -
apiVersion: v1
kind: Pod
metadata:
  name: curl-es
  namespace: default
spec:
  containers:
  - name: curl-container
    image: curlimages/curl
    command: ["/bin/sh", "-c"]
    args:
      - |
        while true; do
          date
          ENCODED_API_KEY=\$(cat /etc/api-key/encoded)
          echo "\$ENCODED_API_KEY"
          curl -ks -H "Authorization: ApiKey \$ENCODED_API_KEY" https://quickstart-es-http.es-cluster.svc:9200/_cluster/health
          echo ""
          sleep 10
        done
    volumeMounts:
    - name: api-key-volume
      mountPath: /etc/api-key
      readOnly: true
  volumes:
  - name: api-key-volume
    secret:
      secretName: my-api-key

EOF
