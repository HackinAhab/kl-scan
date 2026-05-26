package kube

import (
	"fmt"
	"os"

	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

// Client holds a configured Kubernetes clientset and the resolved target namespace.
type Client struct {
	Clientset kubernetes.Interface
	Namespace string // resolved target namespace (empty = all)
}

// Config holds the parameters for building a Kubernetes client.
type Config struct {
	KubeconfigPath string
	ContextName    string
	Namespace      string // explicit -n flag value; empty = use context default
	AllNamespaces  bool   // -A flag
}

// NewClient constructs a Client from the given config.
func NewClient(cfg Config) (*Client, error) {
	loadingRules := clientcmd.NewDefaultClientConfigLoadingRules()
	if cfg.KubeconfigPath != "" {
		loadingRules.ExplicitPath = cfg.KubeconfigPath
	}

	overrides := &clientcmd.ConfigOverrides{}
	if cfg.ContextName != "" {
		overrides.CurrentContext = cfg.ContextName
	}

	kubeConfig := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(
		loadingRules,
		overrides,
	)

	restCfg, err := kubeConfig.ClientConfig()
	if err != nil {
		// Fall back to in-cluster config.
		restCfg, err = rest.InClusterConfig()
		if err != nil {
			return nil, fmt.Errorf("cannot build kube client config: %w", err)
		}
	}

	cs, err := kubernetes.NewForConfig(restCfg)
	if err != nil {
		return nil, fmt.Errorf("cannot build kube clientset: %w", err)
	}

	ns := resolveNamespace(cfg, kubeConfig)

	return &Client{
		Clientset: cs,
		Namespace: ns,
	}, nil
}

// resolveNamespace determines the target namespace from flags and kubeconfig.
//   - AllNamespaces → empty string (caller interprets as "all")
//   - explicit -n <ns> → that namespace
//   - neither → current context's namespace, falling back to "default"
func resolveNamespace(cfg Config, kc clientcmd.ClientConfig) string {
	if cfg.AllNamespaces {
		return ""
	}
	if cfg.Namespace != "" {
		return cfg.Namespace
	}
	// Read current context namespace.
	ns, _, err := kc.Namespace()
	if err != nil || ns == "" {
		// Check KUBECONFIG env-driven namespace.
		if env := os.Getenv("POD_NAMESPACE"); env != "" {
			return env
		}
		return "default"
	}
	return ns
}
