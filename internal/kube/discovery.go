package kube

import (
	"context"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"kl-scan/internal/logger"
)

// PodTarget represents a single (pod, container) pair to stream logs from.
type PodTarget struct {
	Namespace string
	PodName   string
	PodUID    string
	NodeName  string
	Container string
}

// DiscoveryConfig controls which pods are returned.
type DiscoveryConfig struct {
	Namespace     string // empty = all namespaces
	LabelSelector string
	FieldSelector string
}

// DiscoverTargets returns all (pod, container) pairs matching the given config.
// Only Running pods are included; completed/failed/pending pods are skipped.
func DiscoverTargets(ctx context.Context, client *Client, cfg DiscoveryConfig) ([]PodTarget, error) {
	ns := cfg.Namespace

	listOpts := metav1.ListOptions{
		LabelSelector: cfg.LabelSelector,
		FieldSelector: cfg.FieldSelector,
	}

	pods, err := client.Clientset.CoreV1().Pods(ns).List(ctx, listOpts)
	if err != nil {
		return nil, fmt.Errorf("list pods (namespace=%q): %w", ns, err)
	}

	logger.Debugf("list pods  namespace=%q  label=%q  field=%q  total=%d",
		ns, cfg.LabelSelector, cfg.FieldSelector, len(pods.Items))

	var targets []PodTarget
	for i := range pods.Items {
		p := &pods.Items[i]
		if !isPodRunning(p) {
			continue
		}
		for _, c := range p.Spec.Containers {
			targets = append(targets, PodTarget{
				Namespace: p.Namespace,
				PodName:   p.Name,
				PodUID:    string(p.UID),
				NodeName:  p.Spec.NodeName,
				Container: c.Name,
			})
		}
	}
	return targets, nil
}

func isPodRunning(p *corev1.Pod) bool {
	return p.Status.Phase == corev1.PodRunning
}
