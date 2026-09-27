//go:build linux

package fingerprintnet

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

type owner struct {
	PID     int
	Start   string
	Device  string
	Address string
	Table   string
}

type forwardingLease struct {
	Name     string
	Original string
	Owners   map[string]bool
}

type registry struct {
	Owners     map[string]owner
	Forwarding map[int]*forwardingLease
}

func processStart(pid int) string {
	b, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return ""
	}
	end := strings.LastIndexByte(string(b), ')')
	if end < 0 {
		return ""
	}
	fields := strings.Fields(string(b[end+1:]))
	if len(fields) < 20 || fields[0] == "Z" {
		return ""
	}
	return fields[19]
}

// Each network namespace has its own leases, including isolated test namespaces.
// The root-owned directory prevents unprivileged state or symlink injection.
func registryPath() (string, error) {
	const directory = "/run/xray-fingerprint"
	if err := os.MkdirAll(directory, 0700); err != nil {
		return "", err
	}
	var st unix.Stat_t
	if err := unix.Lstat(directory, &st); err != nil {
		return "", err
	}
	if st.Mode&unix.S_IFMT != unix.S_IFDIR || st.Uid != 0 || st.Mode&0077 != 0 {
		return "", fmt.Errorf("%s must be a root-owned directory with mode 0700", directory)
	}
	if err := unix.Stat("/proc/self/ns/net", &st); err != nil {
		return "", err
	}
	boot, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if err != nil {
		return "", err
	}
	return filepath.Join(directory, fmt.Sprintf("%s-%d.json", strings.TrimSpace(string(boot)), st.Ino)), nil
}

func saveRegistry(path string, r *registry) error {
	b, err := json.Marshal(r)
	if err != nil {
		return err
	}
	f, err := os.CreateTemp(filepath.Dir(path), ".state-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if _, err := f.Write(b); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(f.Name(), path)
}

func withRegistry(fn func(*registry, string) error) error {
	path, err := registryPath()
	if err != nil {
		return err
	}
	fd, err := unix.Open(path+".lock", unix.O_CREAT|unix.O_RDWR|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0600)
	if err != nil {
		return err
	}
	defer unix.Close(fd)
	if err := unix.Flock(fd, unix.LOCK_EX); err != nil {
		return err
	}
	defer unix.Flock(fd, unix.LOCK_UN)
	r := &registry{Owners: make(map[string]owner), Forwarding: make(map[int]*forwardingLease)}
	b, err := os.ReadFile(path)
	if err == nil {
		if err := json.Unmarshal(b, r); err != nil {
			return fmt.Errorf("read networking leases: %w", err)
		}
	} else if !os.IsNotExist(err) {
		return err
	}
	// Recover a helper that was itself killed. Never identify ownership by PID
	// alone: PIDs can be reused between runs.
	for token, o := range r.Owners {
		if o.Start == "" || processStart(o.PID) != o.Start {
			if err := cleanupOwner(r, token); err != nil {
				return fmt.Errorf("recover stale networking: %w", err)
			}
		}
	}
	err = fn(r, path)
	return errors.Join(err, saveRegistry(path, r))
}

func forwardingPath(name string) string {
	return "/proc/sys/net/ipv4/conf/" + name + "/forwarding"
}

func acquireForwarding(r *registry, path, token string, link netlink.Link) error {
	a := link.Attrs()
	if strings.ContainsAny(a.Name, "/\x00") {
		return fmt.Errorf("invalid interface name")
	}
	lease := r.Forwarding[a.Index]
	if lease != nil && lease.Name != a.Name {
		return fmt.Errorf("interface changed while forwarding was leased")
	}
	if lease == nil {
		value, err := os.ReadFile(forwardingPath(a.Name))
		if err != nil {
			return err
		}
		lease = &forwardingLease{Name: a.Name, Original: strings.TrimSpace(string(value)), Owners: make(map[string]bool)}
		r.Forwarding[a.Index] = lease
	}
	lease.Owners[token] = true
	// Journal the original value before changing the kernel setting.
	if err := saveRegistry(path, r); err != nil {
		return err
	}
	if err := updateForwardingGuard(a.Index, lease, r.Owners); err != nil {
		return err
	}
	return os.WriteFile(forwardingPath(a.Name), []byte("1\n"), 0600)
}

func cleanupOwner(r *registry, token string) error {
	o, exists := r.Owners[token]
	if !exists {
		return nil
	}
	if err := removeRules(o.Table); err != nil {
		return err
	}
	for index, lease := range r.Forwarding {
		delete(lease.Owners, token)
		if len(lease.Owners) != 0 {
			if err := updateForwardingGuard(index, lease, r.Owners); err != nil {
				return err
			}
			continue
		}
		link, err := netlink.LinkByIndex(index)
		if err == nil && link.Attrs().Name == lease.Name {
			current, err := os.ReadFile(forwardingPath(lease.Name))
			if err != nil {
				return err
			}
			// Do not overwrite a subsequent administrator change to another value.
			if strings.TrimSpace(string(current)) == "1" && lease.Original != "1" {
				if err := os.WriteFile(forwardingPath(lease.Name), []byte(lease.Original+"\n"), 0600); err != nil {
					return err
				}
			}
		} else if err != nil {
			var missing netlink.LinkNotFoundError
			if !errors.As(err, &missing) && !errors.Is(err, unix.ENODEV) {
				return fmt.Errorf("interface %s: %w", strconv.Itoa(index), err)
			}
		}
		if err := updateForwardingGuard(index, lease, r.Owners); err != nil {
			return err
		}
		delete(r.Forwarding, index)
	}
	delete(r.Owners, token)
	return nil
}
