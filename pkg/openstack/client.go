// Package openstack is a minimal OpenStack REST client for the broker:
// password auth, catalog lookup, and the few Nova, Neutron and Glance calls
// the PoC needs. Credentials come from the standard OS_* environment.
package openstack

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

// Client talks to one project in one region.
type Client struct {
	HTTP      *http.Client
	Token     string
	ProjectID string
	endpoints map[string]string
}

// FromEnv authenticates with OS_AUTH_URL, OS_USERNAME, OS_PASSWORD,
// OS_PROJECT_ID, OS_USER_DOMAIN_NAME and OS_REGION_NAME.
func FromEnv(ctx context.Context) (*Client, error) {
	need := func(k string) (string, error) {
		v := os.Getenv(k)
		if v == "" {
			return "", fmt.Errorf("%s is not set", k)
		}
		return v, nil
	}
	authURL, err := need("OS_AUTH_URL")
	if err != nil {
		return nil, err
	}
	user, err := need("OS_USERNAME")
	if err != nil {
		return nil, err
	}
	pass, err := need("OS_PASSWORD")
	if err != nil {
		return nil, err
	}
	project, err := need("OS_PROJECT_ID")
	if err != nil {
		return nil, err
	}
	domain := os.Getenv("OS_USER_DOMAIN_NAME")
	if domain == "" {
		domain = "Default"
	}
	region := os.Getenv("OS_REGION_NAME")

	body := map[string]any{"auth": map[string]any{
		"identity": map[string]any{"methods": []string{"password"}, "password": map[string]any{
			"user": map[string]any{"name": user, "domain": map[string]any{"name": domain}, "password": pass}}},
		"scope": map[string]any{"project": map[string]any{"id": project}},
	}}
	b, _ := json.Marshal(body)
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(authURL, "/")+"/auth/tokens", bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
	c := &Client{HTTP: &http.Client{Timeout: 60 * time.Second}, ProjectID: project, endpoints: map[string]string{}}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
		return nil, fmt.Errorf("keystone: HTTP %d: %s", resp.StatusCode, msg)
	}
	c.Token = resp.Header.Get("X-Subject-Token")
	var tok struct {
		Token struct {
			Catalog []struct {
				Type      string `json:"type"`
				Endpoints []struct {
					Interface string `json:"interface"`
					Region    string `json:"region"`
					URL       string `json:"url"`
				} `json:"endpoints"`
			} `json:"catalog"`
		} `json:"token"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&tok); err != nil {
		return nil, err
	}
	for _, s := range tok.Token.Catalog {
		for _, e := range s.Endpoints {
			if e.Interface == "public" && (region == "" || e.Region == region) {
				c.endpoints[s.Type] = strings.TrimRight(e.URL, "/")
			}
		}
	}
	return c, nil
}

// Do calls service (compute, network, image, volumev3) and decodes into out.
func (c *Client) Do(ctx context.Context, service, method, path string, in, out any) error {
	base, ok := c.endpoints[service]
	if !ok {
		return fmt.Errorf("no %s endpoint in catalog", service)
	}
	var body io.Reader
	if in != nil {
		b, _ := json.Marshal(in)
		body = bytes.NewReader(b)
	}
	req, _ := http.NewRequestWithContext(ctx, method, base+path, body)
	req.Header.Set("X-Auth-Token", c.Token)
	req.Header.Set("Content-Type", "application/json")
	if service == "compute" {
		req.Header.Set("OpenStack-API-Version", "compute 2.79")
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return ErrNotFound
	}
	if resp.StatusCode >= 300 {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
		return fmt.Errorf("%s %s %s: HTTP %d: %s", service, method, path, resp.StatusCode, msg)
	}
	if out != nil && resp.StatusCode != http.StatusNoContent {
		return json.NewDecoder(resp.Body).Decode(out)
	}
	return nil
}

// ErrNotFound is returned for HTTP 404.
var ErrNotFound = errors.New("not found")

// Server is the subset of a Nova server the broker reads.
type Server struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Status  string `json:"status"`
	Created string `json:"created"`
	Flavor  struct {
		OriginalName string `json:"original_name"`
	} `json:"flavor"`
	Image     any                                `json:"image"` // "" when booted from volume
	Addresses map[string][]struct{ Addr string } `json:"addresses"`
	Metadata  map[string]string                  `json:"metadata"`
}

// GetServer reads one server.
func (c *Client) GetServer(ctx context.Context, id string) (Server, error) {
	var r struct {
		Server Server `json:"server"`
	}
	err := c.Do(ctx, "compute", http.MethodGet, "/servers/"+id, nil, &r)
	return r.Server, err
}

// FlavorID returns the ID of a flavor by name.
func (c *Client) FlavorID(ctx context.Context, name string) (string, error) {
	var r struct {
		Flavors []struct{ ID, Name string } `json:"flavors"`
	}
	if err := c.Do(ctx, "compute", http.MethodGet, "/flavors?is_public=None", nil, &r); err != nil {
		return "", err
	}
	for _, f := range r.Flavors {
		if f.Name == name {
			return f.ID, nil
		}
	}
	return "", fmt.Errorf("flavor %q not found", name)
}

// UsageSeconds returns the provider's own meter for a server: Nova's
// os-simple-tenant-usage hours over [start, end], in seconds.
func (c *Client) UsageSeconds(ctx context.Context, serverID string, start, end time.Time) (int64, error) {
	var r struct {
		TenantUsage struct {
			ServerUsages []struct {
				InstanceID string  `json:"instance_id"`
				Hours      float64 `json:"hours"`
			} `json:"server_usages"`
		} `json:"tenant_usage"`
	}
	path := fmt.Sprintf("/os-simple-tenant-usage/%s?start=%s&end=%s", c.ProjectID,
		start.UTC().Format("2006-01-02T15:04:05"), end.UTC().Format("2006-01-02T15:04:05"))
	if err := c.Do(ctx, "compute", http.MethodGet, path, nil, &r); err != nil {
		return 0, err
	}
	for _, u := range r.TenantUsage.ServerUsages {
		if u.InstanceID == serverID {
			return int64(u.Hours * 3600), nil
		}
	}
	return 0, fmt.Errorf("no usage for server %s", serverID)
}

// ServerImageID returns the Glance image a server booted from, following the
// boot volume's image metadata when the server booted from a volume.
func (c *Client) ServerImageID(ctx context.Context, s Server) (string, error) {
	if m, ok := s.Image.(map[string]any); ok {
		if id, ok := m["id"].(string); ok && id != "" {
			return id, nil
		}
	}
	var r struct {
		Server struct {
			Volumes []struct {
				ID string `json:"id"`
			} `json:"os-extended-volumes:volumes_attached"`
		} `json:"server"`
	}
	if err := c.Do(ctx, "compute", http.MethodGet, "/servers/"+s.ID, nil, &r); err != nil {
		return "", err
	}
	for _, v := range r.Server.Volumes {
		var vr struct {
			Volume struct {
				Bootable string            `json:"bootable"`
				Meta     map[string]string `json:"volume_image_metadata"`
			} `json:"volume"`
		}
		if err := c.Do(ctx, "volumev3", http.MethodGet, "/volumes/"+v.ID, nil, &vr); err != nil {
			return "", err
		}
		if vr.Volume.Bootable == "true" && vr.Volume.Meta["image_id"] != "" {
			return vr.Volume.Meta["image_id"], nil
		}
	}
	return "", errors.New("cannot determine the server's image")
}
