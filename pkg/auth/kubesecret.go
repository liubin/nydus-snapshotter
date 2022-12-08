package auth

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"sync"

	"k8s.io/client-go/tools/clientcmd"

	"github.com/containerd/containerd/log"
	"github.com/docker/cli/cli/config/configfile"
	"github.com/pkg/errors"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"
)

var (
	kubeSecretListener *KubeSecretListener
	configMu           sync.Mutex
)

type KubeSecretListener struct {
	dockerConfigs map[string]*configfile.ConfigFile
	informer      cache.SharedIndexInformer
}

func InitKubeSecretListener(ctx context.Context, kubeconfigPath string) error {
	configMu.Lock()
	defer configMu.Unlock()
	if kubeSecretListener != nil {
		return nil
	}
	kubeSecretListener = &KubeSecretListener{
		dockerConfigs: make(map[string]*configfile.ConfigFile),
	}

	if kubeconfigPath != "" {
		_, err := os.Stat(kubeconfigPath)
		if err != nil && !os.IsNotExist(err) {
			log.L.WithError(err).Warningf("kubeconfig does not exist, kubeconfigPath %s", kubeconfigPath)
			return err
		} else if err != nil {
			log.L.WithError(err).Warningf("failed to detect kubeconfig existence, kubeconfigPath %s", kubeconfigPath)
			return err
		}
	}
	loadingRule := clientcmd.NewDefaultClientConfigLoadingRules()
	loadingRule.ExplicitPath = kubeconfigPath
	clientConfig, err := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(
		loadingRule,
		&clientcmd.ConfigOverrides{},
	).ClientConfig()
	if err != nil {
		log.L.WithError(err).Warningf("failed to load kubeconfig")
		return err
	}
	clientset, err := kubernetes.NewForConfig(clientConfig)
	if err != nil {
		log.L.WithError(err).Warningf("failed to create kubernetes client")
		return err
	}
	if err := kubeSecretListener.SyncKubeSecrets(ctx, clientset); err != nil {
		log.L.WithError(err).Warningf("failed to sync secrets")
		return err
	}

	return nil
}

func (kubelistener *KubeSecretListener) addDockerConfig(key string, obj interface{}) error {
	data, ok := obj.(*corev1.Secret).Data[corev1.DockerConfigJsonKey]
	if !ok {
		return fmt.Errorf("failed to get data from new object")
	}
	dockerConfig := configfile.ConfigFile{}
	if err := dockerConfig.LoadFromReader(bytes.NewReader(data)); err != nil {
		return errors.Wrap(err, "failed to load docker config json from secret")
	}
	configMu.Lock()
	kubelistener.dockerConfigs[key] = &dockerConfig
	configMu.Unlock()
	return nil
}

func (kubelistener *KubeSecretListener) deleteDockerConfig(key string) {
	configMu.Lock()
	delete(kubelistener.dockerConfigs, key)
	configMu.Unlock()
}

func (kubelistener *KubeSecretListener) SyncKubeSecrets(ctx context.Context, clientset *kubernetes.Clientset) error {
	log.L.Errorf("SyncKubeSecrets 1111111")

	if kubelistener.informer != nil {
		return nil
	}
	informer := cache.NewSharedIndexInformer(
		&cache.ListWatch{
			ListFunc: func(options metav1.ListOptions) (runtime.Object, error) {
				log.L.Errorf("SyncKubeSecrets 22222")

				options.FieldSelector = "type=" + string(corev1.SecretTypeDockerConfigJson)
				return clientset.CoreV1().Secrets(metav1.NamespaceAll).List(context.Background(), options)
			},
			WatchFunc: func(options metav1.ListOptions) (watch.Interface, error) {
				log.L.Errorf("SyncKubeSecrets 3333")

				options.FieldSelector = "type=" + string(corev1.SecretTypeDockerConfigJson)
				return clientset.CoreV1().Secrets(metav1.NamespaceAll).Watch(context.Background(), options)
			}},
		&corev1.Secret{},
		0,
		cache.Indexers{},
	)
	kubelistener.informer = informer
	kubelistener.informer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			key, err := cache.MetaNamespaceKeyFunc(obj)
			log.L.Errorf("SyncKubeSecrets 4444444 %+v", key)
			log.L.Errorf("SyncKubeSecrets 4444444 %+v", obj)

			if err != nil {
				log.L.WithError(err).Errorf("failed to get key for secret from cache")
				return
			}
			if err := kubelistener.addDockerConfig(key, obj); err != nil {
				log.L.WithError(err).Errorf("failed to add a new dockerconfigjson")
				return
			}
			log.L.Errorf("SyncKubeSecrets 555555555")

		},
		UpdateFunc: func(old, new interface{}) {
			key, err := cache.MetaNamespaceKeyFunc(new)
			if err != nil {
				log.L.WithError(err).Errorf("failed to get key for secret from cache")
				return
			}
			if err := kubelistener.addDockerConfig(key, new); err != nil {
				log.L.WithError(err).Errorf("failed to add a new dockerconfigjson")
				return
			}
		},
		DeleteFunc: func(obj interface{}) {
			key, err := cache.MetaNamespaceKeyFunc(obj)
			if err != nil {
				log.L.WithError(err).Errorf("failed to get key for secret from cache")
			}
			kubelistener.deleteDockerConfig(key)
		}},
	)
	go kubelistener.informer.Run(ctx.Done())
	log.L.Errorf("SyncKubeSecrets 666666666")

	if !cache.WaitForCacheSync(ctx.Done(), informer.HasSynced) {
		return fmt.Errorf("timed out for syncing cache")
	}
	log.L.Errorf("SyncKubeSecrets 777777777")

	return nil
}

func (kubelistener *KubeSecretListener) getCredentialsStore(host string) *PassKeyChain {
	configMu.Lock()
	defer configMu.Unlock()
	log.L.Errorf("getCredentialsStore host %+v", host)
	log.L.Errorf("getCredentialsStore dockerConfigs %+v", kubelistener.dockerConfigs)

	for _, dockerConfig := range kubelistener.dockerConfigs {
		log.L.Errorf("AAAAA getCredentialsStore dockerConfig %+v", dockerConfig)

		// Find the auth for the host.
		authConfig, err := dockerConfig.GetAuthConfig(host)
		if err != nil {
			log.L.WithError(err).Errorf("failed to get auth config for host %s", host)
			continue
		}
		if len(authConfig.Username) != 0 && len(authConfig.Password) != 0 {
			return &PassKeyChain{
				Username: authConfig.Username,
				Password: authConfig.Password,
			}
		}
	}
	return nil
}

func FromKubeSecretDockerConfig(host string) *PassKeyChain {
	if kubeSecretListener != nil {
		return kubeSecretListener.getCredentialsStore(host)
	}
	return nil
}
