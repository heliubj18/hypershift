package util

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/gob"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"testing"
	"time"

	. "github.com/onsi/gomega"
	"github.com/tidwall/gjson"

	configv1 "github.com/openshift/api/config/v1"
	configv1typedclient "github.com/openshift/client-go/config/clientset/versioned/typed/config/v1"

	kauthnv1 "k8s.io/api/authentication/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/kubernetes"
	kauthnv1typedclient "k8s.io/client-go/kubernetes/typed/authentication/v1"
	"k8s.io/client-go/rest"
	clientcmdapi "k8s.io/client-go/tools/clientcmd/api"
)

// ChangeUserForKeycloakExtOIDC changes the user of current CLI session for an Keycloak external OIDC cluster
func ChangeUserForKeycloakExtOIDC(t *testing.T, ctx context.Context, clientCfg *rest.Config) (*rest.Config, error) {
	g := NewWithT(t)
	isExternalOIDCCluster, err := IsExternalOIDCCluster(t, ctx, clientCfg)
	g.Expect(err).NotTo(HaveOccurred(), "Failed to check if the cluster's authentication config is OIDC")
	g.Expect(isExternalOIDCCluster).To(BeTrue(), "The cluster's authentication config is not OIDC")

	c, err := kubernetes.NewForConfig(clientCfg)
	if err != nil {
		return nil, fmt.Errorf("could not create k8s client: %w", err)
	}

	// The KEYCLOAK_* env vars are passed from Prow CI jobs
	if os.Getenv("KEYCLOAK_ISSUER") == "" || os.Getenv("KEYCLOAK_TEST_USERS") == "" || os.Getenv("KEYCLOAK_CLI_CLIENT_ID") == "" {
		return nil, errors.New("KEYCLOAK_ISSUER, KEYCLOAK_TEST_USERS, KEYCLOAK_CLI_CLIENT_ID are required to test external oidc functions, but not all found in env vars")
	}
	keycloakIssuer := os.Getenv("KEYCLOAK_ISSUER")
	keycloakTestUsers := os.Getenv("KEYCLOAK_TEST_USERS")
	// KEYCLOAK_TEST_USERS has format like "user1:password1,user2:password2,...,usern:passwordn" and n (i.e. 50) is enough for parallel running cases
	re := regexp.MustCompile(`([^:,]+):([^,]+)`)
	testUsers := re.FindAllStringSubmatch(keycloakTestUsers, -1)
	usersTotal := len(testUsers)
	var username, password string
	err = wait.PollUntilContextTimeout(ctx, 2*time.Second, 30*time.Second, true, func(ct context.Context) (bool, error) {
		// Pick a random user for current running case to use
		rand.Seed(time.Now().UnixMilli())
		userIndex := rand.Intn(usersTotal)
		username = testUsers[userIndex][1]
		g.Expect(username).NotTo(BeEmpty())
		password = testUsers[userIndex][2]
		g.Expect(password).NotTo(BeEmpty())
		testUserUsedConfigMap := &corev1.ConfigMap{
			ObjectMeta: metav1.ObjectMeta{
				Name:      username+"-being-used",
			},
			Data: map[string]string{"any": "any"},
		}
		// We use the "default" namespace and will clean up the temp configmap
		if testUserUsedConfigMap, err = c.CoreV1().ConfigMaps("default").Create(ct, testUserUsedConfigMap, metav1.CreateOptions{}); err != nil {
			t.Logf("Failed to create the configmap '%s-being-used': %v. Retrying ...", username, err)
			return false, nil
		}

		t.Logf("Random test user for use: '%s'. Marked it being used via a configmap '%s-being-used'.", username, username)
		t.Cleanup(func() {
			t.Logf("Deleting cm/%s", testUserUsedConfigMap.Name)
			// cleanup must use the "ctx" passed to PollUntilContextTimeout, instead of the "ct" passed to the "func"
			err := c.CoreV1().ConfigMaps("default").Delete(ctx, testUserUsedConfigMap.Name, metav1.DeleteOptions{})
			g.Expect(err).NotTo(HaveOccurred(), "Failed to delete cm/%s", testUserUsedConfigMap.Name)
		})
		return true, nil
	})
	g.Expect(err).NotTo(HaveOccurred(), "Failed to pick a random user for current running case to use")

	httpClient := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
		},
	}
	requestURL := keycloakIssuer + "/protocol/openid-connect/token"
	oidcClientID := os.Getenv("KEYCLOAK_CLI_CLIENT_ID")
	g.Expect(oidcClientID).NotTo(BeEmpty())
	formData := url.Values{
		"client_id":  []string{oidcClientID},
		"grant_type": []string{"password"},
		"password":   []string{password},
		"scope":      []string{"openid email profile"},
		"username":   []string{username},
	}

	response, err := httpClient.PostForm(requestURL, formData)
	g.Expect(err).NotTo(HaveOccurred())
	defer response.Body.Close()
	g.Expect(response.StatusCode).To(Equal(http.StatusOK))

	body, err := io.ReadAll(response.Body)
	g.Expect(err).NotTo(HaveOccurred())
	responseStr := string(body)
	idToken := gjson.Get(responseStr, "id_token").String()
	g.Expect(idToken).NotTo(BeEmpty())
	refreshToken := gjson.Get(responseStr, "refresh_token").String()
	g.Expect(refreshToken).NotTo(BeEmpty())
	tokenCache := fmt.Sprintf(`{"id_token":"%s","refresh_token":"%s"}`, idToken, refreshToken)
	// The CI job that uses Keycloak external OIDC already sets Keycloak token lifetime proper to run case.

	// "type Key" is copied from https://github.com/openshift/oc/blob/master/pkg/cli/gettoken/tokencache/tokencache.go
	// We must keep the def of "type Key" as exactly same as original oc repo so that EncodeToString generates correct output
	type Key struct {
		IssuerURL string
		ClientID  string
	}

	key := Key{IssuerURL: keycloakIssuer, ClientID: oidcClientID}
	s := sha256.New()
	e := gob.NewEncoder(s)
	if err := e.Encode(&key); err != nil {
		t.Fatalf("Could not encode the key: %w", err)
	}
	tokenCacheFile := hex.EncodeToString(s.Sum(nil))
	tokenCacheDir, err := os.MkdirTemp("", username)
	t.Cleanup(func() {
		_ = os.RemoveAll(tokenCacheDir)
	})
	g.Expect(err).NotTo(HaveOccurred())
	err = os.Mkdir(tokenCacheDir+"/oc", 0700)
	g.Expect(err).NotTo(HaveOccurred())
	err = os.WriteFile(filepath.Join(tokenCacheDir, "oc", tokenCacheFile), []byte(tokenCache), 0600)
	g.Expect(err).NotTo(HaveOccurred())

	clientConfigForExtOIDCUser := GetClientConfigForExtOIDCUser(t, clientCfg, tokenCacheDir)
	authClient, err := kauthnv1typedclient.NewForConfig(clientConfigForExtOIDCUser)
	if err != nil {
		return nil, err
	}

	selfSubjectReview, err := authClient.SelfSubjectReviews().Create(ctx, &kauthnv1.SelfSubjectReview{}, metav1.CreateOptions{})
	if err != nil {
		return nil, err
	}
	t.Logf("Detected external OIDC cluster using Keycloak as the provider. The user is now %q", selfSubjectReview.Status.UserInfo.Username)
	return clientConfigForExtOIDCUser, nil
}

// GetClientConfigForExtOIDCUser gets a client config for an external OIDC cluster
func GetClientConfigForExtOIDCUser(t *testing.T, clientCfg *rest.Config, tokenCacheDir string) *rest.Config {
	userClientConfig := rest.AnonymousClientConfig(rest.CopyConfig(clientCfg))
	var oidcIssuerURL, oidcClientID, oidcCertCAPath string
	if IsKeycloakExtOIDCCluster() {
		oidcIssuerURL = os.Getenv("KEYCLOAK_ISSUER")
		oidcClientID = os.Getenv("KEYCLOAK_CLI_CLIENT_ID")
	} else {
		t.Fatal("Currently the GetClientConfigForExtOIDCUser func only supports limited external OIDC providers")
	}
	oidcCertCAPath = filepath.Join(os.Getenv("SHARED_DIR"), "oidcProviders-ca.crt")
	args := []string{
		"get-token",
		fmt.Sprintf("--issuer-url=%s", oidcIssuerURL),
		fmt.Sprintf("--client-id=%s", oidcClientID),
		"--extra-scopes=email,profile",
		"--callback-address=127.0.0.1:8080",
	}
	if _, err := os.Stat(oidcCertCAPath); err == nil {
		args = append(args, fmt.Sprintf("--certificate-authority=%s", oidcCertCAPath))
	}
	userClientConfig.ExecProvider = &clientcmdapi.ExecConfig{
		APIVersion: "client.authentication.k8s.io/v1",
		Command:    "oc",
		Args:       args,
		// We can't use os.Setenv("KUBECACHEDIR", tokenCacheDir), so we use "ExecEnvVar" that ensures each
		// single user has unique cache path to avoid the parallel running users mess up the same cache path,
		// because the cache file name is decided by the issuer URL & client ID provided in CLI
		Env: []clientcmdapi.ExecEnvVar{
			{Name: "KUBECACHEDIR", Value: tokenCacheDir},
		},
		InstallHint:        "Please be sure that oc is defined in $PATH to be executed as credentials exec plugin",
		InteractiveMode:    clientcmdapi.IfAvailableExecInteractiveMode,
		ProvideClusterInfo: false,
	}

	return userClientConfig
}

// IsExternalOIDCCluster checks if the cluster is using external OIDC.
func IsExternalOIDCCluster(t *testing.T, ctx context.Context, clientCfg *rest.Config) (bool, error) {
	configv1Client, err := configv1typedclient.NewForConfig(clientCfg)
	if err != nil {
		return false, err
	}
	authConfig, err := configv1Client.Authentications().Get(ctx, "cluster", metav1.GetOptions{})
	if err != nil {
		return false, err
	}
	t.Logf("Found authentication type used: %v", authConfig.Spec.Type)
	return authConfig.Spec.Type == configv1.AuthenticationTypeOIDC, nil
}

// IsKeycloakExtOIDCCluster assumes the cluster uses external oidc auth but checks if the oidc issuer is Keycloak.
func IsKeycloakExtOIDCCluster() bool {
	if os.Getenv("KEYCLOAK_ISSUER") != "" && os.Getenv("KEYCLOAK_TEST_USERS") != "" && os.Getenv("KEYCLOAK_CLI_CLIENT_ID") != "" {
		return true
	}
	return false
}
