# k8s-configmap-orphan-finder
Find ConfigMaps and Secrets that no workload references anymore: scans pod specs for env, envFrom, volumes, imagePullSecrets and service-account references, then reports the leftovers.
