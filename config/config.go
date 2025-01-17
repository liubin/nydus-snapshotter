/*
 * Copyright (c) 2020. Ant Group. All rights reserved.
 * Copyright (c) 2022. Nydus Developers. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package config

import (
	"os"
	"path"
	"path/filepath"
	"time"

	"github.com/pelletier/go-toml"
	"github.com/pkg/errors"
	exec "golang.org/x/sys/execabs"

	"github.com/containerd/containerd/log"
	"github.com/containerd/nydus-snapshotter/cmd/containerd-nydus-grpc/pkg/command"
	"github.com/containerd/nydus-snapshotter/cmd/containerd-nydus-grpc/pkg/logging"
	"github.com/containerd/nydus-snapshotter/pkg/errdefs"
)

// Define a policy how to fork nydusd daemon and attach file system instances to serve.
type DaemonMode string

var SnapshotsDir string

var NydusConfig *Config

const (
	// One nydusd, one rafs instance
	DaemonModeMultiple DaemonMode = "multiple"
	// One nydusd serves multiple rafs instances
	DaemonModeShared DaemonMode = "shared"
	// No nydusd daemon is needed to be started. Snapshotter does not start any nydusd
	// and only interacts with containerd with mount slice to pass necessary configuration
	// to container runtime
	DaemonModeNone    DaemonMode = "none"
	DaemonModeInvalid DaemonMode = ""
)

func parseDaemonMode(m string) (DaemonMode, error) {
	switch m {
	case string(DaemonModeMultiple):
		return DaemonModeMultiple, nil
	case string(DaemonModeShared):
		return DaemonModeShared, nil
	case string(DaemonModeNone):
		return DaemonModeNone, nil
	default:
		return DaemonModeInvalid, errdefs.ErrInvalidArgument
	}
}

const (
	DefaultDaemonMode DaemonMode = DaemonModeMultiple

	DefaultLogLevel string = "info"
	defaultGCPeriod        = 24 * time.Hour

	defaultNydusDaemonConfigPath string = "/etc/nydus/nydusd-config.json"
	nydusdBinaryName             string = "nydusd"
	nydusImageBinaryName         string = "nydus-image"

	defaultRootDir    = "/var/lib/containerd-nydus"
	oldDefaultRootDir = "/var/lib/containerd-nydus-grpc"

	// Log rotation
	defaultRotateLogMaxSize    = 200 // 200 megabytes
	defaultRotateLogMaxBackups = 10
	defaultRotateLogMaxAge     = 0 // days
	defaultRotateLogLocalTime  = true
	defaultRotateLogCompress   = true
)

const (
	FsDriverFusedev string = "fusedev"
	FsDriverFscache string = "fscache"
)

type Config struct {
	Address                  string        `toml:"-"`
	ConvertVpcRegistry       bool          `toml:"-"`
	DaemonCfgPath            string        `toml:"daemon_cfg_path"`
	PublicKeyFile            string        `toml:"-"`
	RootDir                  string        `toml:"-"`
	CacheDir                 string        `toml:"cache_dir"`
	GCPeriod                 time.Duration `toml:"gc_period"`
	ValidateSignature        bool          `toml:"validate_signature"`
	NydusdBinaryPath         string        `toml:"nydusd_binary_path"`
	NydusImageBinaryPath     string        `toml:"nydus_image_binary"`
	DaemonMode               DaemonMode    `toml:"daemon_mode"`
	FsDriver                 string        `toml:"fs_driver"`
	SyncRemove               bool          `toml:"sync_remove"`
	EnableMetrics            bool          `toml:"enable_metrics"`
	MetricsFile              string        `toml:"metrics_file"`
	EnableStargz             bool          `toml:"enable_stargz"`
	LogLevel                 string        `toml:"-"`
	LogDir                   string        `toml:"log_dir"`
	LogToStdout              bool          `toml:"log_to_stdout"`
	DisableCacheManager      bool          `toml:"disable_cache_manager"`
	EnableNydusOverlayFS     bool          `toml:"enable_nydus_overlayfs"`
	NydusdThreadNum          int           `toml:"nydusd_thread_num"`
	CleanupOnClose           bool          `toml:"cleanup_on_close"`
	KubeconfigPath           string        `toml:"kubeconfig_path"`
	EnableKubeconfigKeychain bool          `toml:"enable_kubeconfig_keychain"`
	RotateLogMaxSize         int           `toml:"log_rotate_max_size"`
	RotateLogMaxBackups      int           `toml:"log_rotate_max_backups"`
	RotateLogMaxAge          int           `toml:"log_rotate_max_age"`
	RotateLogLocalTime       bool          `toml:"log_rotate_local_time"`
	RotateLogCompress        bool          `toml:"log_rotate_compress"`
	EnableSystemController   bool          `toml:"enable_system_controller"`
	RecoverPolicy            string        `toml:"recover_policy"`
	EnableCRIKeychain        bool          `toml:"enable_cri_keychain"`
	ImageServiceAddress      string        `toml:"image_service_address"`
}

// Defines snapshots states directories.
func (c *Config) SnapshotRoot() string {
	return filepath.Join(c.RootDir, "snapshots")
}

func (c *Config) SocketRoot() string {
	return filepath.Join(c.RootDir, "socket")
}

func (c *Config) ConfigRoot() string {
	return filepath.Join(c.RootDir, "config")
}

func GetDaemonMode() DaemonMode {
	return NydusConfig.DaemonMode
}

func GetFsDriver() string {
	return NydusConfig.FsDriver
}

type SnapshotterConfig struct {
	StartupFlag command.Args `toml:"snapshotter"`
}

func LoadSnapshotterConfig(snapshotterConfigPath string) (*SnapshotterConfig, error) {
	var config SnapshotterConfig
	// get nydus-snapshotter configuration from specified path of toml file
	if snapshotterConfigPath == "" {
		return nil, errors.New("snapshotter configuration path cannot be empty")
	}
	tree, err := toml.LoadFile(snapshotterConfigPath)
	if err != nil {
		return nil, errors.Wrapf(err, "load snapshotter configuration file %q", snapshotterConfigPath)
	}
	if err = tree.Unmarshal(config); err != nil {
		return nil, errors.Wrapf(err, "unmarshal snapshotter configuration file %q", snapshotterConfigPath)
	}
	return &config, nil
}

func ProcessParameters(args *command.Args, cfg *Config) error {
	if args == nil {
		return errors.New("no startup parameter provided")
	}

	if args.ValidateSignature {
		if args.PublicKeyFile == "" {
			return errors.New("need to specify publicKey file for signature validation")
		} else if _, err := os.Stat(args.PublicKeyFile); err != nil {
			return errors.Wrapf(err, "failed to find publicKey file %q", args.PublicKeyFile)
		}
	}
	cfg.PublicKeyFile = args.PublicKeyFile
	cfg.ValidateSignature = args.ValidateSignature
	cfg.DaemonCfgPath = args.ConfigPath
	daemonMode, err := parseDaemonMode(args.DaemonMode)
	if err != nil {
		return err
	}

	// Give --shared-daemon higher priority
	cfg.DaemonMode = daemonMode
	if args.SharedDaemon {
		cfg.DaemonMode = DaemonModeShared
	}

	if args.FsDriver == FsDriverFscache && daemonMode != DaemonModeShared {
		return errors.New("`fscache` driver only supports `shared` daemon mode")
	}

	cfg.RootDir = args.RootDir
	if len(cfg.RootDir) == 0 {
		return errors.New("empty root directory")
	}

	// Snapshots does not have to bind to any runtime daemon.
	SnapshotsDir = path.Join(cfg.RootDir, "snapshots")

	if args.RootDir == defaultRootDir {
		if entries, err := os.ReadDir(oldDefaultRootDir); err == nil {
			if len(entries) != 0 {
				log.L.Warnf("Default root directory is changed to %s", defaultRootDir)
			}
		}
	}

	cfg.CacheDir = args.CacheDir
	if len(cfg.CacheDir) == 0 {
		cfg.CacheDir = filepath.Join(cfg.RootDir, "cache")
	}

	cfg.LogLevel = args.LogLevel
	// Always let options from CLI override those from configuration file.
	cfg.LogToStdout = args.LogToStdout
	cfg.LogDir = args.LogDir
	if len(cfg.LogDir) == 0 {
		cfg.LogDir = filepath.Join(cfg.RootDir, logging.DefaultLogDirName)
	}
	cfg.RotateLogMaxSize = defaultRotateLogMaxSize
	cfg.RotateLogMaxBackups = defaultRotateLogMaxBackups
	cfg.RotateLogMaxAge = defaultRotateLogMaxAge
	cfg.RotateLogLocalTime = defaultRotateLogLocalTime
	cfg.RotateLogCompress = defaultRotateLogCompress

	d, err := time.ParseDuration(args.GCPeriod)
	if err != nil {
		return errors.Wrapf(err, "parse gc period %v failed", args.GCPeriod)
	}
	cfg.GCPeriod = d

	cfg.Address = args.Address
	cfg.EnableSystemController = args.EnableSystemController
	cfg.CleanupOnClose = args.CleanupOnClose
	cfg.ConvertVpcRegistry = args.ConvertVpcRegistry
	cfg.DisableCacheManager = args.DisableCacheManager

	cfg.EnableStargz = args.EnableStargz
	cfg.EnableNydusOverlayFS = args.EnableNydusOverlayFS
	cfg.FsDriver = args.FsDriver

	cfg.EnableMetrics = args.EnableMetrics
	cfg.MetricsFile = args.MetricsFile

	cfg.NydusdBinaryPath = args.NydusdBinaryPath
	cfg.NydusImageBinaryPath = args.NydusImageBinaryPath
	cfg.NydusdThreadNum = args.NydusdThreadNum

	cfg.SyncRemove = args.SyncRemove

	cfg.KubeconfigPath = args.KubeconfigPath
	cfg.EnableKubeconfigKeychain = args.EnableKubeconfigKeychain
	cfg.EnableCRIKeychain = args.EnableCRIKeychain
	cfg.ImageServiceAddress = args.ImageServiceAddress

	cfg.RecoverPolicy = args.RecoverPolicy

	NydusConfig = cfg

	return cfg.SetupNydusBinaryPaths()
}

func (c *Config) FillUpWithDefaults() error {
	if c.LogLevel == "" {
		c.LogLevel = DefaultLogLevel
	}
	if c.DaemonCfgPath == "" {
		c.DaemonCfgPath = defaultNydusDaemonConfigPath
	}

	if c.DaemonMode == "" {
		c.DaemonMode = DefaultDaemonMode
	}

	if c.GCPeriod == 0 {
		c.GCPeriod = defaultGCPeriod
	}

	if len(c.CacheDir) == 0 {
		c.CacheDir = filepath.Join(c.RootDir, "cache")
	}

	if len(c.LogDir) == 0 {
		c.LogDir = filepath.Join(c.RootDir, logging.DefaultLogDirName)
	}

	return c.SetupNydusBinaryPaths()
}

func (c *Config) SetupNydusBinaryPaths() error {
	// when using DaemonMode = none, nydusd and nydus-image binaries are not required
	if c.DaemonMode == DaemonModeNone {
		return nil
	}

	// resolve nydusd path
	if c.NydusdBinaryPath == "" {
		path, err := exec.LookPath(nydusdBinaryName)
		if err != nil {
			return err
		}
		c.NydusdBinaryPath = path
	}

	// resolve nydus-image path
	if c.NydusImageBinaryPath == "" {
		path, err := exec.LookPath(nydusImageBinaryName)
		if err != nil {
			return err
		}
		c.NydusImageBinaryPath = path
	}

	return nil
}
