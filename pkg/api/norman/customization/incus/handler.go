package incus

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"slices"
	"strings"

	"github.com/gorilla/mux"
	incus "github.com/lxc/incus/v6/client"
	"github.com/rancher/norman/api/access"
	"github.com/rancher/norman/httperror"
	"github.com/rancher/norman/types"
	prov "github.com/rancher/rancher/pkg/apis/provisioning.cattle.io/v1"
	"github.com/rancher/rancher/pkg/auth/util"
	client "github.com/rancher/rancher/pkg/client/generated/management/v3"
	provcluster "github.com/rancher/rancher/pkg/controllers/provisioningv2/cluster"
	provv1 "github.com/rancher/rancher/pkg/generated/controllers/provisioning.cattle.io/v1"
	v1 "github.com/rancher/rancher/pkg/generated/norman/core/v1"
	"github.com/rancher/rancher/pkg/namespace"
	"github.com/rancher/rancher/pkg/ref"
	schema "github.com/rancher/rancher/pkg/schemas/management.cattle.io/v3"
	"github.com/rancher/rancher/pkg/settings"
	"github.com/rancher/rancher/pkg/types/config"
	corev1 "k8s.io/api/core/v1"
)

var fieldNames = []string{
	"ping",
	"projects",
	"profiles",
	"networks",
	"storages",
	"images",
}

var (
	cloudCredentialDataPrefix = "incuscredentialConfig-"
	dataFields                = []string{
		"url",
		"tlsClientCert",
		"tlsClientKey",
	}
	acceptableImages = []string{
		"debian/11/cloud/amd64",
		"debian/12/cloud/amd64",
		"ubuntu/20.04/cloud/amd64",
		"ubuntu/22.04/cloud/amd64",
		"ubuntu/24.04/cloud/amd64",
		"opensuse/15.6/cloud/amd64",
		"fedora/39/cloud/amd64",
		"fedora/40/cloud/amd64",
	}
	availableImages = []string{}
)

type handler struct {
	schemas          *types.Schemas
	secretsLister    v1.SecretLister
	provClusterCache provv1.ClusterCache
	ac               types.AccessControl
}

func NewIncusHandler(scaledContext *config.ScaledContext) http.Handler {
	return &handler{
		schemas:          scaledContext.Schemas,
		secretsLister:    scaledContext.Core.Secrets(namespace.GlobalNamespace).Controller().Lister(),
		provClusterCache: scaledContext.Wrangler.Provisioning.Cluster().Cache(),
		ac:               scaledContext.AccessControl,
	}
}

func (v *handler) ServeHTTP(res http.ResponseWriter, req *http.Request) {
	var err error

	fieldName := mux.Vars(req)["field"]

	project := req.FormValue("project")
	if fieldName == "" || !validFieldName(fieldName) {
		util.ReturnHTTPError(res, req, httperror.NotFound.Status, fmt.Sprintf("%s: invalid field name", httperror.NotFound.Code))
		return
	}

	var cc *corev1.Secret
	var errcode httperror.ErrorCode

	if id := req.FormValue("cloudCredentialId"); id != "" {
		cc, errcode, err = v.getCloudCredential(id, req)
		if err != nil {
			util.ReturnHTTPError(res, req, errcode.Status, fmt.Sprintf("%s: %s", errcode.Code, err.Error()))
			return
		}
	} else if id := req.FormValue("secretId"); id != "" {
		cc, errcode, err = v.getSecret(id, req)
		if err != nil {
			util.ReturnHTTPError(res, req, errcode.Status, fmt.Sprintf("%s: %s", errcode.Code, err.Error()))
			return
		}
	}

	if cc == nil {
		util.ReturnHTTPError(res, req, httperror.NotFound.Status, fmt.Sprintf("%s: cloud credential not found", httperror.NotFound.Code))
		return
	}

	var js []byte

	switch fieldName {
	case "ping":
		var data string
		data, err = getPing(req.Context(), cc)
		if err != nil {
			invalidBody(res, req, err)
			return
		}
		js, err = json.Marshal(map[string]string{"data": data})
	case "projects":
		var data []string
		data, err = getProjects(req.Context(), cc)
		if err != nil {
			invalidBody(res, req, err)
			return
		}
		js, err = json.Marshal(map[string][]string{"data": data})
	case "networks":
		var data []string
		data, err = getNetworks(req.Context(), cc)
		if err != nil {
			invalidBody(res, req, err)
			return
		}
		js, err = json.Marshal(map[string][]string{"data": data})
	case "storages":
		var data []string
		data, err = getStorages(req.Context(), cc)
		if err != nil {
			invalidBody(res, req, err)
			return
		}
		js, err = json.Marshal(map[string][]string{"data": data})
	case "images":
		var data []string
		data, err = getImages(req.Context(), cc, project)
		if err != nil {
			invalidBody(res, req, err)
			return
		}
		js, err = json.Marshal(map[string][]string{"data": data})
	case "profiles":
		var data []string
		data, err = getProfiles(req.Context(), cc, project)
		if err != nil {
			invalidBody(res, req, err)
			return
		}
		js, err = json.Marshal(map[string][]string{"data": data})
	}

	if err != nil {
		util.ReturnHTTPError(res, req, httperror.ServerError.Status, fmt.Sprintf("%s: %s", httperror.ServerError.Code, err.Error()))
		return
	}

	res.Header().Set("Content-Type", "application/json")
	res.Write(js)
}

func (v *handler) getCloudCredential(id string, req *http.Request) (*corev1.Secret, httperror.ErrorCode, error) {
	apiContext := v.generateAPIContext(req)
	if err := access.ByID(apiContext, &schema.Version, client.CloudCredentialType, id, &client.CloudCredentialClient{}); err != nil {
		if apiError, ok := err.(*httperror.APIError); ok {
			if apiError.Code.Status == httperror.PermissionDenied.Status || apiError.Code.Status == httperror.NotFound.Status {
				// If the user doesn't have direct access to the cloud credential, then we check if the user
				// has access to a cluster that uses the cloud credential.
				var clusters []*prov.Cluster
				clusters, err = v.provClusterCache.GetByIndex(provcluster.ByCloudCred, id)
				if err != nil || len(clusters) == 0 {
					return nil, httperror.NotFound, fmt.Errorf("cloud credential not found")
				}
				for _, cluster := range clusters {
					if err = access.ByID(apiContext, &schema.Version, client.ClusterType, cluster.Status.ClusterName, &client.Cluster{}); err == nil {
						break
					}
				}
			}
		}
		if err != nil {
			return nil, httperror.NotFound, err
		}
	}

	ns, name := ref.Parse(id)
	if ns == "" || name == "" {
		return nil, httperror.InvalidBodyContent, fmt.Errorf("invalid cloud credential %s", id)
	}

	cc, err := v.secretsLister.Get(namespace.GlobalNamespace, name)
	if err != nil || cc == nil {
		return nil, httperror.InvalidBodyContent, fmt.Errorf("error getting cloud cred %s: %v", id, err)
	}

	if cc.Data == nil || len(cc.Data) == 0 {
		return nil, httperror.InvalidBodyContent, fmt.Errorf("empty credential ID data %s", id)
	}
	if !validCloudCredential(cc) {
		return nil, httperror.InvalidBodyContent, fmt.Errorf("not a valid incus credential %s", id)
	}

	return moveData(cc), httperror.ErrorCode{}, nil
}

func (v *handler) getSecret(id string, req *http.Request) (*corev1.Secret, httperror.ErrorCode, error) {
	defaultNamespace := settings.FleetDefaultWorkspaceName.Get()

	secretState := map[string]interface{}{
		"name":        id,
		"id":          id,
		"namespaceId": defaultNamespace,
	}
	schema := types.Schema{ID: "secrets"}

	if err := v.ac.CanDo(v1.SecretGroupVersionKind.Group, v1.SecretResource.Name,
		"get", v.generateAPIContext(req), secretState, &schema); err != nil {
		return nil, httperror.InvalidBodyContent, fmt.Errorf("not a valid incus credential %s", id)
	}

	cc, err := v.secretsLister.Get(defaultNamespace, id)
	if err != nil || cc == nil {
		return nil, httperror.InvalidBodyContent, fmt.Errorf("error getting cloud cred %s: %v", id, err)
	}

	if cc.Data == nil || len(cc.Data) == 0 {
		return nil, httperror.InvalidBodyContent, fmt.Errorf("empty secret ID data %s", id)
	}

	if !validSecret(cc) {
		return nil, httperror.InvalidBodyContent, fmt.Errorf("not a valid incus credential %s", id)
	}

	return cc, httperror.ErrorCode{}, nil
}

func (v *handler) generateAPIContext(req *http.Request) *types.APIContext {
	return &types.APIContext{
		Method:  req.Method,
		Request: req,
		Schemas: v.schemas,
		Query:   map[string][]string{},
	}
}

func invalidBody(res http.ResponseWriter, req *http.Request, err error) {
	util.ReturnHTTPError(res, req, httperror.InvalidBodyContent.Status, fmt.Sprintf("%s: %s", httperror.InvalidBodyContent.Code, err.Error()))
}

func validFieldName(s string) bool {
	return slices.Contains(fieldNames, s)
}

func validCloudCredential(cc *corev1.Secret) bool {
	for _, v := range dataFields {
		if _, ok := cc.Data[cloudCredentialDataPrefix+v]; !ok {
			return false
		}
	}

	return true
}

// takes an old cloud credential and moves the data to the new secret location
func moveData(cc *corev1.Secret) *corev1.Secret {
	copy := cc.DeepCopy()
	for _, v := range dataFields {
		n, ok := cc.Data[cloudCredentialDataPrefix+v]
		if !ok {
			continue
		}
		copy.Data[v] = n
	}
	return copy
}

func validSecret(cc *corev1.Secret) bool {
	for _, v := range dataFields {
		if _, ok := cc.Data[v]; !ok {
			return false
		}
	}
	return true
}

func getIncus(ctx context.Context, cc *corev1.Secret) (incus.InstanceServer, error) {
	args := &incus.ConnectionArgs{
		TLSClientCert:      string(cc.Data["tlsClientCert"]),
		TLSClientKey:       string(cc.Data["tlsClientKey"]),
		InsecureSkipVerify: true,
	}

	is, err := incus.ConnectIncusWithContext(ctx, string(cc.Data["url"]), args)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to incus: " + err.Error())
	}

	return is, nil
}

func getPing(ctx context.Context, cc *corev1.Secret) (string, error) {
	client, err := getIncus(ctx, cc)
	if err != nil {
		return "", err
	}

	_, etag, err := client.GetServer()
	if err != nil {
		return "", err
	}

	if etag == "" {
		return "", fmt.Errorf("Not authenticated")
	}
	return etag, nil
}

func getProjects(ctx context.Context, cc *corev1.Secret) ([]string, error) {
	client, err := getIncus(ctx, cc)
	if err != nil {
		return nil, err
	}

	projects, err := client.GetProjectNames()
	if err != nil {
		return nil, err
	}

	return projects, nil
}

func getNetworks(ctx context.Context, cc *corev1.Secret) ([]string, error) {
	client, err := getIncus(ctx, cc)
	if err != nil {
		return nil, err
	}

	networks, err := client.GetNetworks()
	if err != nil {
		return nil, err
	}

	// for now only support bridge and ovn only
	nets := []string{}
	for _, net := range networks {
		if slices.Contains([]string{"bridge", "ovn"}, net.Type) {
			nets = append(nets, net.Name)
		}
	}
	return nets, nil
}

func getStorages(ctx context.Context, cc *corev1.Secret) ([]string, error) {
	client, err := getIncus(ctx, cc)
	if err != nil {
		return nil, err
	}

	return client.GetStoragePoolNames()
}

func getImages(ctx context.Context, cc *corev1.Secret, project string) ([]string, error) {
	if len(availableImages) > 0 {
		return availableImages, nil
	}

	client, err := getIncus(ctx, cc)
	if err != nil {
		return nil, err
	}

	client, err = useProject(client, project)
	if err != nil {
		return nil, err
	}

	imgs := []string{}
	// get images from existing local and remote
	localImgs, err := client.GetImageAliasNames()
	if err != nil {
		return nil, err
	}

	for _, limg := range localImgs {
		if strings.Contains(limg, "cloud") && !strings.Contains(limg, "amd64") {
			imgs = append(imgs, limg)
		}
	}

	imageServer := "https://images.linuxcontainers.org"
	imgSrv, err := incus.ConnectSimpleStreams(imageServer, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to image server: %w", err)
	}

	remoteImgs, err := imgSrv.GetImages()
	if err != nil {
		return nil, err
	}

	for _, rimg := range remoteImgs {
		if rimg.Type != "virtual-machine" || rimg.Architecture != "x86_64" {
			continue
		}
		if len(rimg.Aliases) == 0 {
			continue
		}
		for _, alias := range rimg.Aliases {
			for _, img := range acceptableImages {
				if alias.Name == img {
					availableImages = append(availableImages, img)
				}
			}
		}
	}

	return availableImages, nil
}

func getProfiles(ctx context.Context, cc *corev1.Secret, project string) ([]string, error) {
	client, err := getIncus(ctx, cc)
	if err != nil {
		return nil, err
	}

	client, err = useProject(client, project)
	if err != nil {
		return nil, err
	}

	return client.GetProfileNames()
}

func useProject(client incus.InstanceServer, project string) (incus.InstanceServer, error) {
	if _, _, err := client.GetProject(project); err != nil {
		return nil, fmt.Errorf("project %s not found: %w", project, err)
	}

	return client.UseProject(project), nil
}
