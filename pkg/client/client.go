// Package client provides utilities to initialize and interact with the Kubernetes API Server.
package client

import (
	"log/slog"
	"os"
	"path"

	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
)

// fileExists 检查指定路径是否为一个已存在的文件（而非目录）
func fileExists(filePath string) bool {
	fileInfo, err := os.Stat(filePath)
	if err == nil && fileInfo.IsDir() == false {
		return true
	}
	return false
}

// GetDefaultKubeConfigFile 按优先级依次探测 kubeconfig 文件的默认路径。
func GetDefaultKubeConfigFile() string {
	home, _ := os.UserHomeDir()
	DefaultConfigPaths := [...]string{
		os.Getenv("kubeConfig"),
		os.Getenv("KUBECONFIG"),
		path.Join(home, ".kube/config"),
		"/etc/kubernetes/admin.conf",
		"/root/.kube/config",
	}

	for _, kubeConfig := range DefaultConfigPaths {
		if kubeConfig != "" && fileExists(kubeConfig) {
			return kubeConfig
		}
	}

	return ""
}

// BuildClientSet build clientSet by kubeconfig
func BuildClientSet(kubeconfig string) (*kubernetes.Clientset, error) {
	config, err := clientcmd.BuildConfigFromFlags("", kubeconfig)
	if err != nil {
		return nil, err
	}
	slog.Info("Config loaded from file", "path", kubeconfig)

	clientSet, err := kubernetes.NewForConfig(config)
	if err != nil {
		return nil, err
	}

	return clientSet, nil
}
