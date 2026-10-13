// Package config loads the Go runtime's deployment contract from the environment.
package config

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/certificate"
)

const (
	DatabaseSQLite     = "sqlite"
	DatabaseMySQL      = "mysql"
	DeploymentBusiness = "business"
	DeploymentStorage  = "only_stroge"
)

// Config is the Go deployment contract. Defaults preserve frontend behavior
// while selecting SQLite unless DB_TYPE explicitly requests MySQL.
type Config struct {
	DeploymentMode         string
	StorageEndpoint        string
	StorageTransport       string
	StoragePort            int
	DatabaseType           string
	SQLitePath             string
	MySQLHost              string
	MySQLPort              int
	MySQLDatabase          string
	MySQLUser              string
	MySQLPasswordFile      string
	RedisURL               string
	MediaCatalogCacheTTL   int
	HTTPAddress            string
	DataRoot               string
	StaticRoot             string
	SecretsDirectory       string
	ServerName             string
	PublicOrigin           string
	TLSEnabled             bool
	NginxMedia             bool
	STUNPort               int
	WebRTCCooldown         int
	AdminSessionTTL        int
	AdminFailedWindow      int
	AdminMaxFailed         int
	AdminCookieSameSite    string
	AdminMaxUploadBytes    int64
	AdminMaxTaskFiles      int
	AdminMaxBatchFiles     int
	AdminMaxDownloadItems  int
	AdminMaxFilenameLength int
	AdminUploadInactivity  int
	TrustedProxyNetworks   []string
	SecurityExemptNetworks []string
	SecurityInvalidLimit   int
	SecurityInvalidWindow  int
	SecurityContact        string
	LogLevel               string
	LogFormat              string
	GitHubAPIToken         string
	ReleaseBranch          string
	ReleaseSourceBranch    string
}

// Load reads configuration from the process environment.
func Load() (Config, error) {
	file, err := readDotEnv(".env")
	if err != nil {
		return Config{}, err
	}
	return LoadFrom(func(key string) string {
		if value, exists := os.LookupEnv(key); exists {
			return value
		}
		return file[key]
	})
}

// LoadFrom makes configuration parsing deterministic in tests.
func LoadFrom(getenv func(string) string) (Config, error) {
	reportRetiredTLS(getenv)
	if err := validateRetiredPublicPorts(getenv); err != nil {
		return Config{}, err
	}
	port, err := integer(getenv("MYSQL_PORT"), 3306)
	if err != nil || port < 1 || port > 65535 {
		return Config{}, errors.New("MYSQL_PORT must be an integer from 1 to 65535")
	}
	value := Config{
		DeploymentMode:    normalized(getenv("DEPLOYMENT_MODE"), DeploymentBusiness),
		StorageEndpoint:   strings.TrimSpace(getenv("STORAGE_ENDPOINT")),
		StorageTransport:  normalized(getenv("STORAGE_TRANSPORT"), "direct"),
		DatabaseType:      normalized(getenv("DB_TYPE"), DatabaseSQLite),
		SQLitePath:        fallback(getenv("SQLITE_PATH"), "/data/frontiercloud.db"),
		MySQLHost:         fallback(getenv("MYSQL_HOST"), "mysql"),
		MySQLPort:         port,
		MySQLDatabase:     fallback(getenv("MYSQL_DATABASE"), "office_automation"),
		MySQLUser:         fallback(getenv("MYSQL_USER"), "media_admin"),
		MySQLPasswordFile: fallback(getenv("MYSQL_PASSWORD_FILE"), "/run/frontiercloud-secrets/mysql_password"),
		RedisURL:          fallback(getenv("REDIS_URL"), "redis://redis:6379/0"),
		HTTPAddress:       fallback(getenv("HTTP_ADDR"), ":8000"),
		DataRoot:          fallback(getenv("DATA_ROOT"), "/app/data"),
		StaticRoot:        fallback(getenv("STATIC_ROOT"), "/app/static"),
		SecretsDirectory:  fallback(getenv("SECRETS_DIR"), "/run/frontiercloud-secrets"),
		ServerName:        strings.ToLower(strings.TrimSpace(fallback(getenv("SERVER_NAME"), "localhost"))),
	}
	value.SecurityExemptNetworks = strings.Split(fallback(getenv("SECURITY_EXEMPT_NETWORKS"), "127.0.0.0/8,::1/128"), ",")
	value.SecurityContact = strings.TrimSpace(getenv("SECURITY_CONTACT"))
	if value.SecurityContact != "" {
		contact, e := url.Parse(value.SecurityContact)
		if e != nil || len(value.SecurityContact) > 2048 || strings.ContainsAny(value.SecurityContact, "\r\n\t ") || contact.User != nil || contact.Fragment != "" || contact.RawQuery != "" ||
			!(contact.Scheme == "https" && contact.Hostname() != "" || contact.Scheme == "mailto" && strings.Count(contact.Opaque, "@") == 1 && !strings.HasPrefix(contact.Opaque, "@") && !strings.HasSuffix(contact.Opaque, "@")) {
			return Config{}, errors.New("SECURITY_CONTACT must be one real HTTPS reporting URL or mailto address")
		}
	}
	value.GitHubAPIToken = strings.TrimSpace(getenv("GITHUB_API_TOKEN"))
	if len(value.GitHubAPIToken) > 4096 || strings.ContainsAny(value.GitHubAPIToken, "\r\n") {
		return Config{}, errors.New("invalid GITHUB_API_TOKEN")
	}
	value.ReleaseBranch = fallback(getenv("RELEASE_BRANCH"), "main")
	value.ReleaseSourceBranch = fallback(getenv("RELEASE_SOURCE_BRANCH"), "dev")
	if strings.TrimSpace(getenv("RELEASE_MANIFEST_PATH")) != "" {
		return Config{}, errors.New("whole-cluster release manifests are retired")
	}
	if value.ReleaseBranch != "main" || value.ReleaseSourceBranch != "dev" {
		return Config{}, errors.New("FrontierCloud-Gin release policy must select main/dev")
	}
	value.MediaCatalogCacheTTL, err = integer(getenv("MEDIA_CATALOG_CACHE_TTL"), 300)
	if err != nil || value.MediaCatalogCacheTTL < 0 || value.MediaCatalogCacheTTL > 86400 {
		return Config{}, errors.New("MEDIA_CATALOG_CACHE_TTL must be between 0 and 86400")
	}
	value.SecurityInvalidLimit, err = integer(getenv("SECURITY_INVALID_API_LIMIT"), 5)
	if err != nil || value.SecurityInvalidLimit < 1 || value.SecurityInvalidLimit > 100000 {
		return Config{}, errors.New("invalid SECURITY_INVALID_API_LIMIT")
	}
	value.SecurityInvalidWindow, err = integer(getenv("SECURITY_INVALID_API_WINDOW"), 3600)
	if err != nil || value.SecurityInvalidWindow < 1 || value.SecurityInvalidWindow > 315360000 {
		return Config{}, errors.New("invalid SECURITY_INVALID_API_WINDOW")
	}
	value.LogLevel = strings.ToUpper(fallback(getenv("LOG_LEVEL"), "INFO"))
	switch value.LogLevel {
	case "DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL":
	default:
		return Config{}, errors.New("invalid LOG_LEVEL")
	}
	value.LogFormat = normalized(getenv("LOG_FORMAT"), "json")
	if value.LogFormat != "json" && value.LogFormat != "text" {
		return Config{}, errors.New("invalid LOG_FORMAT")
	}
	value.TLSEnabled, err = boolean(getenv("TLS_ENABLED"), false)
	if err != nil {
		return Config{}, fmt.Errorf("TLS_ENABLED: %w", err)
	}

	value.NginxMedia, err = boolean(getenv("NGINX_MEDIA_ACCEL"), true)
	if err != nil {
		return Config{}, fmt.Errorf("NGINX_MEDIA_ACCEL: %w", err)
	}
	value.STUNPort, err = integer(getenv("WEBRTC_STUN_PORT"), 3478)
	if err != nil || value.STUNPort < 1 || value.STUNPort > 65535 {
		return Config{}, errors.New("invalid WEBRTC_STUN_PORT")
	}
	value.WebRTCCooldown, err = integer(getenv("WEBRTC_REPORT_COOLDOWN"), 30)
	if err != nil || value.WebRTCCooldown < 10 || value.WebRTCCooldown > 3600 {
		return Config{}, errors.New("invalid WEBRTC_REPORT_COOLDOWN")
	}
	if value.TLSEnabled && !certificate.Hostname(value.ServerName) {
		return Config{}, errors.New("SERVER_NAME must be a DNS hostname for automatic TLS")
	}
	value.PublicOrigin, err = publicOrigin(value, getenv)
	if err != nil {
		return Config{}, err
	}
	if value.SQLitePath == ":memory:" {
		return Config{}, errors.New("SQLITE_PATH must name a persistent database file")
	}
	value.AdminSessionTTL, err = integer(getenv("ADMIN_SESSION_TTL"), 10800)
	if err != nil || value.AdminSessionTTL < 1 {
		return Config{}, errors.New("invalid ADMIN_SESSION_TTL")
	}
	value.AdminFailedWindow, err = integer(getenv("ADMIN_FAILED_WINDOW"), 300)
	if err != nil || value.AdminFailedWindow < 1 {
		return Config{}, errors.New("invalid ADMIN_FAILED_WINDOW")
	}
	value.AdminMaxFailed, err = integer(getenv("ADMIN_MAX_FAILED_ATTEMPTS_PER_IP"), 10)
	if err != nil || value.AdminMaxFailed < 1 {
		return Config{}, errors.New("invalid ADMIN_MAX_FAILED_ATTEMPTS_PER_IP")
	}
	value.AdminCookieSameSite = normalized(getenv("ADMIN_COOKIE_SAMESITE"), "strict")
	if value.AdminCookieSameSite != "strict" && value.AdminCookieSameSite != "lax" {
		return Config{}, errors.New("ADMIN_COOKIE_SAMESITE must be strict or lax")
	}
	value.AdminMaxUploadBytes = 17 * 512 * 1024 * 1024
	if raw := getenv("ADMIN_MAX_UPLOAD_FILE_SIZE"); raw != "" {
		value.AdminMaxUploadBytes, err = strconv.ParseInt(raw, 10, 64)
		if err != nil || value.AdminMaxUploadBytes < 1 {
			return Config{}, errors.New("invalid ADMIN_MAX_UPLOAD_FILE_SIZE")
		}
	}
	value.AdminMaxTaskFiles, err = integer(getenv("ADMIN_MAX_UPLOAD_TASK_FILES"), 5000)
	if err != nil || value.AdminMaxTaskFiles < 1 {
		return Config{}, errors.New("invalid ADMIN_MAX_UPLOAD_TASK_FILES")
	}
	value.AdminMaxBatchFiles, err = integer(getenv("ADMIN_MAX_BATCH_FILES"), 200)
	if err != nil || value.AdminMaxBatchFiles < 1 {
		return Config{}, errors.New("invalid ADMIN_MAX_BATCH_FILES")
	}
	value.AdminMaxDownloadItems, err = integer(getenv("ADMIN_MAX_DOWNLOAD_ITEMS"), 100)
	if err != nil || value.AdminMaxDownloadItems < 1 {
		return Config{}, errors.New("invalid ADMIN_MAX_DOWNLOAD_ITEMS")
	}
	value.AdminMaxFilenameLength, err = integer(getenv("ADMIN_MAX_FILENAME_LENGTH"), 240)
	if err != nil || value.AdminMaxFilenameLength < 1 {
		return Config{}, errors.New("invalid ADMIN_MAX_FILENAME_LENGTH")
	}
	value.AdminUploadInactivity, err = integer(getenv("ADMIN_UPLOAD_INACTIVITY_TIMEOUT"), 300)
	if err != nil || value.AdminUploadInactivity < 1 {
		return Config{}, errors.New("invalid ADMIN_UPLOAD_INACTIVITY_TIMEOUT")
	}
	value.TrustedProxyNetworks = strings.Split(fallback(getenv("TRUSTED_PROXY_NETWORKS"), "172.16.0.0/12"), ",")
	for _, p := range []*string{&value.DataRoot, &value.StaticRoot, &value.SecretsDirectory} {
		absolute, err := filepath.Abs(*p)
		if err != nil {
			return Config{}, err
		}
		*p = absolute
	}
	if value.DatabaseType != DatabaseSQLite && value.DatabaseType != DatabaseMySQL {
		return Config{}, fmt.Errorf("DB_TYPE must be %q or %q", DatabaseSQLite, DatabaseMySQL)
	}
	if value.DatabaseType == DatabaseSQLite && strings.TrimSpace(value.SQLitePath) == "" {
		return Config{}, errors.New("SQLITE_PATH is required when DB_TYPE=sqlite")
	}
	if value.DeploymentMode != DeploymentBusiness && value.DeploymentMode != DeploymentStorage {
		return Config{}, errors.New("DEPLOYMENT_MODE must be business or only_stroge")
	}
	if value.DeploymentMode == DeploymentStorage {
		if value.DatabaseType != DatabaseSQLite || !value.TLSEnabled || value.NginxMedia {
			return Config{}, errors.New("only_stroge requires embedded SQLite, TLS_ENABLED=true and NGINX_MEDIA_ACCEL=false")
		}
		if value.StorageTransport != "direct" && value.StorageTransport != "relay" {
			return Config{}, errors.New("STORAGE_TRANSPORT must be direct or relay")
		}
		defaultPort := 443
		if value.StorageTransport == "relay" {
			defaultPort = 8443
		}
		value.StoragePort, err = integer(getenv("STORAGE_PORT"), defaultPort)
		if err != nil || value.StorageTransport == "direct" && value.StoragePort != 443 || value.StorageTransport == "relay" && (value.StoragePort < 1024 || value.StoragePort > 65535) {
			return Config{}, errors.New("direct storage requires port 443; relay storage requires a private communication port from 1024 through 65535")
		}
		endpoint, e := url.Parse(value.StorageEndpoint)
		if e != nil || endpoint.Scheme != "https" || !strings.EqualFold(endpoint.Hostname(), value.ServerName) || endpoint.User != nil || endpoint.RawQuery != "" || endpoint.ForceQuery || endpoint.Fragment != "" || endpoint.Path != "" || endpoint.RawPath != "" || endpoint.Opaque != "" {
			return Config{}, errors.New("STORAGE_ENDPOINT must be a certificate-verified HTTPS root URL matching SERVER_NAME")
		}
		endpointPort := 443
		if endpoint.Port() != "" {
			endpointPort, e = strconv.Atoi(endpoint.Port())
		}
		if e != nil || endpointPort != value.StoragePort {
			return Config{}, errors.New("STORAGE_ENDPOINT port must match the direct or relay deployment profile")
		}
		value.HTTPAddress = fallback(getenv("HTTP_ADDR"), ":"+strconv.Itoa(value.StoragePort))
		_, port, e := net.SplitHostPort(value.HTTPAddress)
		if e != nil || port != strconv.Itoa(value.StoragePort) {
			return Config{}, errors.New("storage HTTP_ADDR must match the enforced storage transport port")
		}
	}
	return value, nil
}

// Discovery URLs use operator configuration, never a request Host header.
// Public HTTP(S) always uses its standard port, including external proxies.
func publicOrigin(value Config, getenv func(string) string) (string, error) {
	raw := strings.TrimSpace(getenv("PUBLIC_ORIGIN"))
	if raw == "" {
		scheme := "http"
		if value.TLSEnabled {
			scheme = "https"
		}
		host := value.ServerName
		if strings.Contains(host, ":") && !strings.HasPrefix(host, "[") {
			host = "[" + host + "]"
		}
		raw = (&url.URL{Scheme: scheme, Host: host}).String()
	}
	origin, err := url.Parse(raw)
	if err != nil || strings.ContainsAny(raw, "\r\n\t ") || origin.User != nil || origin.RawQuery != "" || origin.ForceQuery || origin.Fragment != "" || origin.Opaque != "" || origin.RawPath != "" ||
		(origin.Path != "" && origin.Path != "/") || (origin.Scheme != "http" && origin.Scheme != "https") || !strings.EqualFold(origin.Hostname(), strings.Trim(value.ServerName, "[]")) {
		return "", errors.New("PUBLIC_ORIGIN must be an HTTP(S) origin matching SERVER_NAME, without credentials, path, query or fragment")
	}
	if err := PublicPort(origin); err != nil {
		return "", fmt.Errorf("PUBLIC_ORIGIN: %w", err)
	}
	if value.TLSEnabled && origin.Scheme != "https" || !value.TLSEnabled && origin.Scheme != "http" {
		return "", errors.New("PUBLIC_ORIGIN scheme must match TLS_ENABLED")
	}
	origin.Path = ""
	return origin.String(), nil
}

func boolean(value string, defaultValue bool) (bool, error) {
	if strings.TrimSpace(value) == "" {
		return defaultValue, nil
	}
	return strconv.ParseBool(strings.TrimSpace(value))
}

func (c Config) AdminCookieName() string {
	if c.TLSEnabled {
		return "__Host-admin_session"
	}
	return "admin_session"
}
func (c Config) CSRFCookieName() string {
	if c.TLSEnabled {
		return "__Host-admin-csrf"
	}
	return "admin_csrf"
}

func fallback(value, defaultValue string) string {
	if strings.TrimSpace(value) == "" {
		return defaultValue
	}
	return strings.TrimSpace(value)
}

func normalized(value, defaultValue string) string {
	return strings.ToLower(fallback(value, defaultValue))
}

func integer(value string, defaultValue int) (int, error) {
	if strings.TrimSpace(value) == "" {
		return defaultValue, nil
	}
	return strconv.Atoi(strings.TrimSpace(value))
}
