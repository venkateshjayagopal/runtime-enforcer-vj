package resolver

import "github.com/rancher-sandbox/runtime-enforcer/api/v1alpha1"

// containerInfo is the internal representation of a container's information.
type containerInfo struct {
	cgID CgroupID
	name ContainerName
}

// podInfo is the internal representation of a pod's information.
type podInfo struct {
	podID        string
	namespace    string
	name         string
	workloadName string
	workloadType string
	labels       Labels
}

type podState struct {
	info       *podInfo
	containers map[ContainerID]*containerInfo
}

func (pod *podState) matchPolicy(policyName, policyNamespace string) bool {
	v, ok := pod.info.labels[v1alpha1.PolicyLabelKey]
	if !ok || v != policyName {
		return false
	}

	// now we need to check if the pod is in the same namespace of the policy since our policies are namespaced.
	if pod.info.namespace != policyNamespace {
		return false
	}

	return true
}

func (pod *podState) policyLabel() string {
	return pod.info.labels[v1alpha1.PolicyLabelKey]
}

func (pod *podState) podName() string {
	return pod.info.name
}

func (pod *podState) podNamespace() string {
	return pod.info.namespace
}
