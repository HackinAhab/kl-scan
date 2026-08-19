package kube

import (
	"context"
	"fmt"
	"sort"
	"sync"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/tools/cache"

	"kl-scan/internal/logger"
)

// TargetKey is a stable identifier for a (pod, container) pair across pod
// recreations (uses PodUID, not PodName).
type TargetKey struct {
	Namespace string
	PodUID    string
	Container string
}

// String renders the key in "ns/podUID/container" form.
func (k TargetKey) String() string {
	return k.Namespace + "/" + k.PodUID + "/" + k.Container
}

// IndexConfig configures a TargetIndex.
type IndexConfig struct {
	Namespaces    []string // nil/empty = all namespaces
	LabelSelector string
	FieldSelector string
	ResyncPeriod  time.Duration
}

// TargetIndex maintains an authoritative, live view of running pod containers
// using a SharedInformer. It exposes Snapshot() for the rotator.
type TargetIndex struct {
	cfg       IndexConfig
	factories []informers.SharedInformerFactory

	mu      sync.RWMutex
	targets map[TargetKey]PodTarget

	syncedCh chan struct{}
	once     sync.Once
}

// NewTargetIndex constructs a TargetIndex (does not start it; call Run).
func NewTargetIndex(client *Client, cfg IndexConfig) (*TargetIndex, error) {
	if cfg.ResyncPeriod <= 0 {
		cfg.ResyncPeriod = 5 * time.Minute
	}

	// Validate selectors early so we fail fast.
	if cfg.LabelSelector != "" {
		if _, err := labels.Parse(cfg.LabelSelector); err != nil {
			return nil, fmt.Errorf("invalid label selector: %w", err)
		}
	}
	if cfg.FieldSelector != "" {
		if _, err := fields.ParseSelector(cfg.FieldSelector); err != nil {
			return nil, fmt.Errorf("invalid field selector: %w", err)
		}
	}

	namespaces := cfg.Namespaces
	if len(namespaces) == 0 {
		namespaces = []string{""}
	}

	idx := &TargetIndex{
		cfg:       cfg,
		factories: make([]informers.SharedInformerFactory, 0, len(namespaces)),
		targets:   make(map[TargetKey]PodTarget),
		syncedCh:  make(chan struct{}),
	}

	tweakOpts := func(o *metav1.ListOptions) {
		o.LabelSelector = cfg.LabelSelector
		o.FieldSelector = cfg.FieldSelector
	}

	for _, ns := range namespaces {
		factory := informers.NewSharedInformerFactoryWithOptions(
			client.Clientset,
			cfg.ResyncPeriod,
			informers.WithNamespace(ns),
			informers.WithTweakListOptions(tweakOpts),
		)
		podInformer := factory.Core().V1().Pods().Informer()
		_, err := podInformer.AddEventHandler(cache.ResourceEventHandlerFuncs{
			AddFunc:    idx.onAdd,
			UpdateFunc: idx.onUpdate,
			DeleteFunc: idx.onDelete,
		})
		if err != nil {
			return nil, fmt.Errorf("register pod event handler (namespace=%q): %w", ns, err)
		}
		idx.factories = append(idx.factories, factory)
	}

	return idx, nil
}

// Run starts the informer factories and blocks until ctx is done.
// It signals readiness on the channel returned by Synced once all caches are
// initially populated.
func (i *TargetIndex) Run(ctx context.Context) error {
	for _, f := range i.factories {
		f.Start(ctx.Done())
	}

	for _, f := range i.factories {
		synced := f.WaitForCacheSync(ctx.Done())
		for v, ok := range synced {
			if !ok {
				return fmt.Errorf("informer cache failed to sync for %v", v)
			}
		}
	}
	i.once.Do(func() { close(i.syncedCh) })

	<-ctx.Done()
	return nil
}

// Synced returns a channel closed once the initial cache has populated.
func (i *TargetIndex) Synced() <-chan struct{} {
	return i.syncedCh
}

// Snapshot returns a stable, sorted slice of the current running targets.
func (i *TargetIndex) Snapshot() []PodTarget {
	i.mu.RLock()
	defer i.mu.RUnlock()

	out := make([]PodTarget, 0, len(i.targets))
	for _, t := range i.targets {
		out = append(out, t)
	}
	sort.Slice(out, func(a, b int) bool {
		if out[a].Namespace != out[b].Namespace {
			return out[a].Namespace < out[b].Namespace
		}
		if out[a].PodName != out[b].PodName {
			return out[a].PodName < out[b].PodName
		}
		return out[a].Container < out[b].Container
	})
	return out
}

// --- event handlers ---------------------------------------------------------

func (i *TargetIndex) onAdd(obj any) {
	if p, ok := obj.(*corev1.Pod); ok {
		i.applyPod(p)
	}
}

func (i *TargetIndex) onUpdate(_ any, newObj any) {
	if p, ok := newObj.(*corev1.Pod); ok {
		i.applyPod(p)
	}
}

func (i *TargetIndex) onDelete(obj any) {
	switch v := obj.(type) {
	case *corev1.Pod:
		i.removePod(v)
	case cache.DeletedFinalStateUnknown:
		if p, ok := v.Obj.(*corev1.Pod); ok {
			i.removePod(p)
		}
	}
}

// applyPod inserts the pod's containers into the index if Running, otherwise
// removes them.
func (i *TargetIndex) applyPod(p *corev1.Pod) {
	if !isPodRunning(p) {
		i.removePod(p)
		return
	}

	i.mu.Lock()
	defer i.mu.Unlock()

	for _, c := range p.Spec.Containers {
		k := TargetKey{
			Namespace: p.Namespace,
			PodUID:    string(p.UID),
			Container: c.Name,
		}
		if _, ok := i.targets[k]; !ok {
			logger.Infof("index add  %s/%s [%s]  uid=%s", p.Namespace, p.Name, c.Name, p.UID)
		}
		i.targets[k] = PodTarget{
			Namespace: p.Namespace,
			PodName:   p.Name,
			PodUID:    string(p.UID),
			NodeName:  p.Spec.NodeName,
			Container: c.Name,
		}
	}
}

// removePod removes all of the pod's container targets from the index.
func (i *TargetIndex) removePod(p *corev1.Pod) {
	i.mu.Lock()
	defer i.mu.Unlock()

	for _, c := range p.Spec.Containers {
		k := TargetKey{
			Namespace: p.Namespace,
			PodUID:    string(p.UID),
			Container: c.Name,
		}
		if _, ok := i.targets[k]; ok {
			logger.Infof("index del  %s/%s [%s]", p.Namespace, p.Name, c.Name)
			delete(i.targets, k)
		}
	}
}

// TargetKeyOf returns the TargetKey for a given PodTarget.
func TargetKeyOf(t PodTarget) TargetKey {
	return TargetKey{
		Namespace: t.Namespace,
		PodUID:    t.PodUID,
		Container: t.Container,
	}
}
