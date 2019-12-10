package swift

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/Unknwon/com"
	"github.com/gophercloud/gophercloud"
	"github.com/gophercloud/gophercloud/openstack"
	"github.com/gophercloud/utils/openstack/clientconfig"

	"github.com/hashicorp/terraform/backend"
	"github.com/hashicorp/terraform/helper/pathorcontents"
	"github.com/hashicorp/terraform/helper/schema"
	"github.com/hashicorp/terraform/terraform"
)

// List of headers that need to be redacted
var REDACT_HEADERS = []string{"x-auth-token", "x-auth-key", "x-service-token",
	"x-storage-token", "x-account-meta-temp-url-key", "x-account-meta-temp-url-key-2",
	"x-container-meta-temp-url-key", "x-container-meta-temp-url-key-2", "set-cookie",
	"x-subject-token"}

// New creates a new backend for Swift remote state.
func New() backend.Backend {
	s := &schema.Backend{
		Schema: map[string]*schema.Schema{
			"auth_url": &schema.Schema{
				Type:        schema.TypeString,
				Required:    true,
				DefaultFunc: schema.EnvDefaultFunc("OS_AUTH_URL", ""),
				Description: descriptions["auth_url"],
			},

			"user_id": &schema.Schema{
				Type:        schema.TypeString,
				Optional:    true,
				DefaultFunc: schema.EnvDefaultFunc("OS_USER_ID", ""),
				Description: descriptions["user_name"],
			},

			"user_name": &schema.Schema{
				Type:        schema.TypeString,
				Optional:    true,
				DefaultFunc: schema.EnvDefaultFunc("OS_USERNAME", ""),
				Description: descriptions["user_name"],
			},

			"application_credential_id": &schema.Schema{
				Type:        schema.TypeString,
				Optional:    true,
				DefaultFunc: schema.EnvDefaultFunc("OS_APPLICATION_CREDENTIAL_ID", ""),
				Description: descriptions["application_credential_id"],
			},

			"application_credential_name": &schema.Schema{
				Type:        schema.TypeString,
				Optional:    true,
				DefaultFunc: schema.EnvDefaultFunc("OS_APPLICATION_CREDENTIAL_NAME", ""),
				Description: descriptions["application_credential_name"],
			},

			"application_credential_secret": &schema.Schema{
				Type:        schema.TypeString,
				Optional:    true,
				DefaultFunc: schema.EnvDefaultFunc("OS_APPLICATION_CREDENTIAL_SECRET", ""),
				Description: descriptions["application_credential_secret"],
			},

			"tenant_id": &schema.Schema{
				Type:     schema.TypeString,
				Optional: true,
				DefaultFunc: schema.MultiEnvDefaultFunc([]string{
					"OS_TENANT_ID",
					"OS_PROJECT_ID",
				}, ""),
				Description: descriptions["tenant_id"],
			},

			"tenant_name": &schema.Schema{
				Type:     schema.TypeString,
				Optional: true,
				DefaultFunc: schema.MultiEnvDefaultFunc([]string{
					"OS_TENANT_NAME",
					"OS_PROJECT_NAME",
				}, ""),
				Description: descriptions["tenant_name"],
			},

			"password": &schema.Schema{
				Type:        schema.TypeString,
				Optional:    true,
				Sensitive:   true,
				DefaultFunc: schema.EnvDefaultFunc("OS_PASSWORD", ""),
				Description: descriptions["password"],
			},

			"token": &schema.Schema{
				Type:     schema.TypeString,
				Optional: true,
				DefaultFunc: schema.MultiEnvDefaultFunc([]string{
					"OS_TOKEN",
					"OS_AUTH_TOKEN",
				}, ""),
				Description: descriptions["token"],
			},

			"user_domain_name": &schema.Schema{
				Type:        schema.TypeString,
				Optional:    true,
				DefaultFunc: schema.EnvDefaultFunc("OS_USER_DOMAIN_NAME", ""),
				Description: descriptions["user_domain_name"],
			},

			"user_domain_id": &schema.Schema{
				Type:        schema.TypeString,
				Optional:    true,
				DefaultFunc: schema.EnvDefaultFunc("OS_USER_DOMAIN_ID", ""),
				Description: descriptions["user_domain_id"],
			},

			"project_domain_name": &schema.Schema{
				Type:        schema.TypeString,
				Optional:    true,
				DefaultFunc: schema.EnvDefaultFunc("OS_PROJECT_DOMAIN_NAME", ""),
				Description: descriptions["project_domain_name"],
			},

			"project_domain_id": &schema.Schema{
				Type:        schema.TypeString,
				Optional:    true,
				DefaultFunc: schema.EnvDefaultFunc("OS_PROJECT_DOMAIN_ID", ""),
				Description: descriptions["project_domain_id"],
			},

			"domain_id": &schema.Schema{
				Type:        schema.TypeString,
				Optional:    true,
				DefaultFunc: schema.EnvDefaultFunc("OS_DOMAIN_ID", ""),
				Description: descriptions["domain_id"],
			},

			"domain_name": &schema.Schema{
				Type:        schema.TypeString,
				Optional:    true,
				DefaultFunc: schema.EnvDefaultFunc("OS_DOMAIN_NAME", ""),
				Description: descriptions["domain_name"],
			},

			"default_domain": &schema.Schema{
				Type:        schema.TypeString,
				Optional:    true,
				DefaultFunc: schema.EnvDefaultFunc("OS_DEFAULT_DOMAIN", "default"),
				Description: descriptions["default_domain"],
			},

			"cloud": &schema.Schema{
				Type:        schema.TypeString,
				Optional:    true,
				DefaultFunc: schema.EnvDefaultFunc("OS_CLOUD", ""),
				Description: descriptions["cloud"],
			},

			"region_name": &schema.Schema{
				Type:        schema.TypeString,
				Required:    true,
				DefaultFunc: schema.EnvDefaultFunc("OS_REGION_NAME", ""),
				Description: descriptions["region_name"],
			},

			"insecure": &schema.Schema{
				Type:        schema.TypeBool,
				Optional:    true,
				DefaultFunc: schema.EnvDefaultFunc("OS_INSECURE", nil),
				Description: descriptions["insecure"],
			},

			"endpoint_type": &schema.Schema{
				Type:        schema.TypeString,
				Optional:    true,
				DefaultFunc: schema.EnvDefaultFunc("OS_ENDPOINT_TYPE", ""),
			},

			"cacert_file": &schema.Schema{
				Type:        schema.TypeString,
				Optional:    true,
				DefaultFunc: schema.EnvDefaultFunc("OS_CACERT", ""),
				Description: descriptions["cacert_file"],
			},

			"cert": &schema.Schema{
				Type:        schema.TypeString,
				Optional:    true,
				DefaultFunc: schema.EnvDefaultFunc("OS_CERT", ""),
				Description: descriptions["cert"],
			},

			"key": &schema.Schema{
				Type:        schema.TypeString,
				Optional:    true,
				DefaultFunc: schema.EnvDefaultFunc("OS_KEY", ""),
				Description: descriptions["key"],
			},

			"path": &schema.Schema{
				Type:          schema.TypeString,
				Optional:      true,
				Description:   descriptions["path"],
				Deprecated:    "Use container instead",
				ConflictsWith: []string{"container"},
			},

			"container": &schema.Schema{
				Type:        schema.TypeString,
				Optional:    true,
				Description: descriptions["container"],
			},

			"archive_path": &schema.Schema{
				Type:          schema.TypeString,
				Optional:      true,
				Description:   descriptions["archive_path"],
				Deprecated:    "Use archive_container instead",
				ConflictsWith: []string{"archive_container"},
			},

			"archive_container": &schema.Schema{
				Type:        schema.TypeString,
				Optional:    true,
				Description: descriptions["archive_container"],
			},

			"expire_after": &schema.Schema{
				Type:        schema.TypeString,
				Optional:    true,
				Description: descriptions["expire_after"],
			},

			"lock": &schema.Schema{
				Type:        schema.TypeBool,
				Optional:    true,
				Description: "Lock state access",
				Default:     true,
			},

			"state_name": &schema.Schema{
				Type:        schema.TypeString,
				Optional:    true,
				Description: descriptions["state_name"],
				Default:     "tfstate.tf",
			},
		},
	}

	result := &Backend{Backend: s}
	result.Backend.ConfigureFunc = result.configure
	return result
}

var descriptions map[string]string

func init() {
	descriptions = map[string]string{
		"auth_url": "The Identity authentication URL.",

		"user_name": "Username to login with.",

		"user_id": "User ID to login with.",

		"application_credential_id": "Application Credential ID to login with.",

		"application_credential_name": "Application Credential name to login with.",

		"application_credential_secret": "Application Credential secret to login with.",

		"tenant_id": "The ID of the Tenant (Identity v2) or Project (Identity v3)\n" +
			"to login with.",

		"tenant_name": "The name of the Tenant (Identity v2) or Project (Identity v3)\n" +
			"to login with.",

		"password": "Password to login with.",

		"token": "Authentication token to use as an alternative to username/password.",

		"user_domain_name": "The name of the domain where the user resides (Identity v3).",

		"user_domain_id": "The ID of the domain where the user resides (Identity v3).",

		"project_domain_name": "The name of the domain where the project resides (Identity v3).",

		"project_domain_id": "The ID of the domain where the proejct resides (Identity v3).",

		"domain_id": "The ID of the Domain to scope to (Identity v3).",

		"domain_name": "The name of the Domain to scope to (Identity v3).",

		"default_domain": "The name of the Domain ID to scope to if no other domain is specified. Defaults to `default` (Identity v3).",

		"cloud": "An entry in a `clouds.yaml` file to use.",

		"region_name": "The name of the Region to use.",

		"insecure": "Trust self-signed certificates.",

		"cacert_file": "A Custom CA certificate.",

		"endpoint_type": "The catalog endpoint type to use.",

		"cert": "A client certificate to authenticate with.",

		"key": "A client private key to authenticate with.",

		"path": "Swift container path to use.",

		"container": "Swift container to create",

		"archive_path": "Swift container path to archive state to.",

		"archive_container": "Swift container to archive state to.",

		"expire_after": "Archive object expiry duration.",

		"state_name": "Name of state object in container",
	}
}

type Backend struct {
	*schema.Backend

	// Fields below are set from configure
	client           *gophercloud.ServiceClient
	archive          bool
	archiveContainer string
	expireSecs       int
	container        string
	lock             bool
	stateName        string
}

func (b *Backend) configure(ctx context.Context) error {
	if b.client != nil {
		return nil
	}

	// Grab the resource data
	data := schema.FromContextBackendConfig(ctx)
	config := &Config{
		CACertFile:                  data.Get("cacert_file").(string),
		ClientCertFile:              data.Get("cert").(string),
		ClientKeyFile:               data.Get("key").(string),
		Cloud:                       data.Get("cloud").(string),
		DefaultDomain:               data.Get("default_domain").(string),
		DomainID:                    data.Get("domain_id").(string),
		DomainName:                  data.Get("domain_name").(string),
		EndpointType:                data.Get("endpoint_type").(string),
		IdentityEndpoint:            data.Get("auth_url").(string),
		Password:                    data.Get("password").(string),
		ProjectDomainID:             data.Get("project_domain_id").(string),
		ProjectDomainName:           data.Get("project_domain_name").(string),
		Token:                       data.Get("token").(string),
		TenantID:                    data.Get("tenant_id").(string),
		TenantName:                  data.Get("tenant_name").(string),
		UserDomainID:                data.Get("user_domain_id").(string),
		UserDomainName:              data.Get("user_domain_name").(string),
		Username:                    data.Get("user_name").(string),
		UserID:                      data.Get("user_id").(string),
		ApplicationCredentialID:     data.Get("application_credential_id").(string),
		ApplicationCredentialName:   data.Get("application_credential_name").(string),
		ApplicationCredentialSecret: data.Get("application_credential_secret").(string),
	}

	if v, ok := data.GetOkExists("insecure"); ok {
		insecure := v.(bool)
		config.Insecure = &insecure
	}

	if err := config.LoadAndValidate(); err != nil {
		return err
	}

	// Assign state name
	b.stateName = data.Get("state_name").(string)

	// Assign Container
	b.container = data.Get("container").(string)
	if b.container == "" {
		// Check deprecated field
		b.container = data.Get("path").(string)
	}

	// Store the lock information
	b.lock = data.Get("lock").(bool)

	// Enable object archiving?
	if archiveContainer, ok := data.GetOk("archive_container"); ok {
		log.Printf("[DEBUG] Archive_container set, enabling object versioning")
		b.archive = true
		b.archiveContainer = archiveContainer.(string)
	} else if archivePath, ok := data.GetOk("archive_path"); ok {
		log.Printf("[DEBUG] Archive_path set, enabling object versioning")
		b.archive = true
		b.archiveContainer = archivePath.(string)
	}

	// Enable object expiry?
	if expireRaw, ok := data.GetOk("expire_after"); ok {
		expire := expireRaw.(string)
		log.Printf("[DEBUG] Requested that remote state expires after %s", expire)

		if strings.HasSuffix(expire, "d") {
			log.Printf("[DEBUG] Got a days expire after duration. Converting to hours")
			days, err := strconv.Atoi(expire[:len(expire)-1])
			if err != nil {
				return fmt.Errorf("Error converting expire_after value %s to int: %s", expire, err)
			}

			expire = fmt.Sprintf("%dh", days*24)
			log.Printf("[DEBUG] Expire after %s hours", expire)
		}

		expireDur, err := time.ParseDuration(expire)
		if err != nil {
			log.Printf("[DEBUG] Error parsing duration %s: %s", expire, err)
			return fmt.Errorf("Error parsing expire_after duration '%s': %s", expire, err)
		}
		log.Printf("[DEBUG] Seconds duration = %d", int(expireDur.Seconds()))
		b.expireSecs = int(expireDur.Seconds())
	}

	objClient, err := openstack.NewObjectStorageV1(config.OsClient, gophercloud.EndpointOpts{
		Region: data.Get("region_name").(string),
	})
	if err != nil {
		return err
	}

	b.client = objClient

	return nil
}

type Config struct {
	CACertFile                  string
	ClientCertFile              string
	ClientKeyFile               string
	Cloud                       string
	DefaultDomain               string
	DomainID                    string
	DomainName                  string
	EndpointOverrides           map[string]interface{}
	EndpointType                string
	IdentityEndpoint            string
	Insecure                    *bool
	Password                    string
	ProjectDomainName           string
	ProjectDomainID             string
	Region                      string
	Swauth                      bool
	TenantID                    string
	TenantName                  string
	Token                       string
	UserDomainName              string
	UserDomainID                string
	Username                    string
	UserID                      string
	ApplicationCredentialID     string
	ApplicationCredentialName   string
	ApplicationCredentialSecret string
	useOctavia                  bool
	MaxRetries                  int

	OsClient *gophercloud.ProviderClient
}

type LogRoundTripper struct {
	Rt         http.RoundTripper
	OsDebug    bool
	MaxRetries int
}

// LoadAndValidate performs the authentication and initial configuration
// of an OpenStack Provider Client. This sets up the HTTP client and
// authenticates to an OpenStack cloud.
//
// Individual Service Clients are created later in this file.
func (c *Config) LoadAndValidate() error {
	// Make sure at least one of auth_url or cloud was specified.
	if c.IdentityEndpoint == "" && c.Cloud == "" {
		return fmt.Errorf("One of 'auth_url' or 'cloud' must be specified")
	}

	validEndpoint := false
	validEndpoints := []string{
		"internal", "internalURL",
		"admin", "adminURL",
		"public", "publicURL",
		"",
	}

	for _, endpoint := range validEndpoints {
		if c.EndpointType == endpoint {
			validEndpoint = true
		}
	}

	if !validEndpoint {
		return fmt.Errorf("Invalid endpoint type provided")
	}

	clientOpts := new(clientconfig.ClientOpts)

	// If a cloud entry was given, base AuthOptions on a clouds.yaml file.
	if c.Cloud != "" {
		clientOpts.Cloud = c.Cloud

		cloud, err := clientconfig.GetCloudFromYAML(clientOpts)
		if err != nil {
			return err
		}

		if c.Region == "" && cloud.RegionName != "" {
			c.Region = cloud.RegionName
		}

		if c.CACertFile == "" && cloud.CACertFile != "" {
			c.CACertFile = cloud.CACertFile
		}

		if c.ClientCertFile == "" && cloud.ClientCertFile != "" {
			c.ClientCertFile = cloud.ClientCertFile
		}

		if c.ClientKeyFile == "" && cloud.ClientKeyFile != "" {
			c.ClientKeyFile = cloud.ClientKeyFile
		}

		if c.Insecure == nil && cloud.Verify != nil {
			v := (!*cloud.Verify)
			c.Insecure = &v
		}
	} else {
		authInfo := &clientconfig.AuthInfo{
			AuthURL:                     c.IdentityEndpoint,
			DefaultDomain:               c.DefaultDomain,
			DomainID:                    c.DomainID,
			DomainName:                  c.DomainName,
			Password:                    c.Password,
			ProjectDomainID:             c.ProjectDomainID,
			ProjectDomainName:           c.ProjectDomainName,
			ProjectID:                   c.TenantID,
			ProjectName:                 c.TenantName,
			Token:                       c.Token,
			UserDomainID:                c.UserDomainID,
			UserDomainName:              c.UserDomainName,
			Username:                    c.Username,
			UserID:                      c.UserID,
			ApplicationCredentialID:     c.ApplicationCredentialID,
			ApplicationCredentialName:   c.ApplicationCredentialName,
			ApplicationCredentialSecret: c.ApplicationCredentialSecret,
		}
		clientOpts.AuthInfo = authInfo
	}

	ao, err := clientconfig.AuthOptions(clientOpts)
	if err != nil {
		return err
	}

	client, err := openstack.NewClient(ao.IdentityEndpoint)
	if err != nil {
		return err
	}

	// Set UserAgent
	client.UserAgent.Prepend(terraform.UserAgentString())

	config := &tls.Config{}
	if c.CACertFile != "" {
		caCert, _, err := pathorcontents.Read(c.CACertFile)
		if err != nil {
			return fmt.Errorf("Error reading CA Cert: %s", err)
		}

		caCertPool := x509.NewCertPool()
		caCertPool.AppendCertsFromPEM([]byte(caCert))
		config.RootCAs = caCertPool
	}

	if c.Insecure == nil {
		config.InsecureSkipVerify = false
	} else {
		config.InsecureSkipVerify = *c.Insecure
	}

	if c.ClientCertFile != "" && c.ClientKeyFile != "" {
		clientCert, _, err := pathorcontents.Read(c.ClientCertFile)
		if err != nil {
			return fmt.Errorf("Error reading Client Cert: %s", err)
		}
		clientKey, _, err := pathorcontents.Read(c.ClientKeyFile)
		if err != nil {
			return fmt.Errorf("Error reading Client Key: %s", err)
		}

		cert, err := tls.X509KeyPair([]byte(clientCert), []byte(clientKey))
		if err != nil {
			return err
		}

		config.Certificates = []tls.Certificate{cert}
		config.BuildNameToCertificate()
	}

	// if OS_DEBUG is set, log the requests and responses
	var osDebug bool
	if os.Getenv("OS_DEBUG") != "" {
		osDebug = true
	}

	transport := &http.Transport{Proxy: http.ProxyFromEnvironment, TLSClientConfig: config}
	client.HTTPClient = http.Client{
		Transport: &LogRoundTripper{
			Rt:         transport,
			OsDebug:    osDebug,
			MaxRetries: c.MaxRetries,
		},
	}

	// If using Swift Authentication, there's no need to validate authentication normally.
	if !c.Swauth {
		err = openstack.Authenticate(client, *ao)
		if err != nil {
			return err
		}
	}

	if c.MaxRetries < 0 {
		return fmt.Errorf("max_retries should be a positive value")
	}

	c.OsClient = client

	return nil
}

func (lrt *LogRoundTripper) RoundTrip(request *http.Request) (*http.Response, error) {
	defer func() {
		if request.Body != nil {
			request.Body.Close()
		}
	}()

	// for future reference, this is how to access the Transport struct:
	//tlsconfig := lrt.Rt.(*http.Transport).TLSClientConfig

	var err error

	if lrt.OsDebug {
		log.Printf("[DEBUG] OpenStack Request URL: %s %s", request.Method, request.URL)
		log.Printf("[DEBUG] OpenStack Request Headers:\n%s", FormatHeaders(request.Header, "\n"))

		if request.Body != nil {
			request.Body, err = lrt.logRequest(request.Body, request.Header.Get("Content-Type"))
			if err != nil {
				return nil, err
			}
		}
	}

	response, err := lrt.Rt.RoundTrip(request)

	// If the first request didn't return a response, retry up to `max_retries`.
	retry := 1
	for response == nil {
		if retry > lrt.MaxRetries {
			if lrt.OsDebug {
				log.Printf("[DEBUG] OpenStack connection error, retries exhausted. Aborting")
			}
			err = fmt.Errorf("OpenStack connection error, retries exhausted. Aborting. Last error was: %s", err)
			return nil, err
		}

		if lrt.OsDebug {
			log.Printf("[DEBUG] OpenStack connection error, retry number %d: %s", retry, err)
		}
		response, err = lrt.Rt.RoundTrip(request)
		retry++
	}

	if lrt.OsDebug {
		log.Printf("[DEBUG] OpenStack Response Code: %d", response.StatusCode)
		log.Printf("[DEBUG] OpenStack Response Headers:\n%s", FormatHeaders(response.Header, "\n"))

		response.Body, err = lrt.logResponse(response.Body, response.Header.Get("Content-Type"))
	}

	return response, err
}

// logResponse will log the HTTP Response details.
// If the body is JSON, it will attempt to be pretty-formatted.
func (lrt *LogRoundTripper) logResponse(original io.ReadCloser, contentType string) (io.ReadCloser, error) {
	if strings.HasPrefix(contentType, "application/json") {
		var bs bytes.Buffer
		defer original.Close()
		_, err := io.Copy(&bs, original)
		if err != nil {
			return nil, err
		}
		debugInfo := lrt.formatJSON(bs.Bytes())
		if debugInfo != "" {
			log.Printf("[DEBUG] OpenStack Response Body: %s", debugInfo)
		}
		return ioutil.NopCloser(strings.NewReader(bs.String())), nil
	}

	log.Printf("[DEBUG] Not logging because OpenStack response body isn't JSON")
	return original, nil
}

// logRequest will log the HTTP Request details.
// If the body is JSON, it will attempt to be pretty-formatted.
func (lrt *LogRoundTripper) logRequest(original io.ReadCloser, contentType string) (io.ReadCloser, error) {
	defer original.Close()

	var bs bytes.Buffer
	_, err := io.Copy(&bs, original)
	if err != nil {
		return nil, err
	}

	// Handle request contentType
	if strings.HasPrefix(contentType, "application/json") {
		debugInfo := lrt.formatJSON(bs.Bytes())
		log.Printf("[DEBUG] OpenStack Request Body: %s", debugInfo)
	}

	return ioutil.NopCloser(strings.NewReader(bs.String())), nil
}

// formatJSON will try to pretty-format a JSON body.
// It will also mask known fields which contain sensitive information.
func (lrt *LogRoundTripper) formatJSON(raw []byte) string {
	var data map[string]interface{}

	err := json.Unmarshal(raw, &data)
	if err != nil {
		log.Printf("[DEBUG] Unable to parse OpenStack JSON: %s", err)
		return string(raw)
	}

	// Mask known password fields
	if v, ok := data["auth"].(map[string]interface{}); ok {
		if v, ok := v["identity"].(map[string]interface{}); ok {
			if v, ok := v["password"].(map[string]interface{}); ok {
				if v, ok := v["user"].(map[string]interface{}); ok {
					v["password"] = "***"
				}
			}
			if v, ok := v["application_credential"].(map[string]interface{}); ok {
				v["secret"] = "***"
			}
			if v, ok := v["token"].(map[string]interface{}); ok {
				v["id"] = "***"
			}
		}
	}

	// Ignore the catalog
	if v, ok := data["token"].(map[string]interface{}); ok {
		if _, ok := v["catalog"]; ok {
			return ""
		}
	}

	pretty, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		log.Printf("[DEBUG] Unable to re-marshal OpenStack JSON: %s", err)
		return string(raw)
	}

	return string(pretty)
}

// FormatHeaders processes a headers object plus a deliminator, returning a string
func FormatHeaders(headers http.Header, seperator string) string {
	redactedHeaders := RedactHeaders(headers)
	sort.Strings(redactedHeaders)

	return strings.Join(redactedHeaders, seperator)
}

// RedactHeaders processes a headers object, returning a redacted list
func RedactHeaders(headers http.Header) (processedHeaders []string) {
	for name, header := range headers {
		for _, v := range header {
			if com.IsSliceContainsStr(REDACT_HEADERS, name) {
				processedHeaders = append(processedHeaders, fmt.Sprintf("%v: %v", name, "***"))
			} else {
				processedHeaders = append(processedHeaders, fmt.Sprintf("%v: %v", name, v))
			}
		}
	}
	return
}
