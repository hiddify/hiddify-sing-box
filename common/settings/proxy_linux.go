//go:build linux && !android

package settings

import (
	"context"
	"net"
	"os"
	"os/exec"
	"os/user"
	"strconv"
	"strings"
	"time"

	"github.com/sagernet/sing/common"
	E "github.com/sagernet/sing/common/exceptions"
	F "github.com/sagernet/sing/common/format"
	M "github.com/sagernet/sing/common/metadata"
	"github.com/sagernet/sing/common/shell"
)

type LinuxSystemProxy struct {
	execute         func(name string, args ...string) error
	hasGSettings    bool
	kWriteConfigCmd string
	serverAddr      M.Socksaddr
	supportSOCKS    bool
	isEnabled       bool
}

func NewSystemProxy(ctx context.Context, serverAddr M.Socksaddr, supportSOCKS bool, bypassDomain []string) (*LinuxSystemProxy, error) {
	var desktopUser *user.User
	if os.Getuid() == 0 {
		desktopUser = invokingUser()
	}
	return NewLinuxSystemProxy(serverAddr, supportSOCKS, func(name string, args ...string) error {
		if os.Getuid() != 0 {
			return shell.Exec(name, args...).Attach().Run()
		} else if desktopUser != nil {
			command := F.ToString(name, " ", strings.Join(args, " "))
			// su starts a login shell without the user's desktop session: gsettings would write to a
			// throwaway backend and kwriteconfig could not reach KDE, on Wayland and X11 alike.
			if bus := userSessionBus(desktopUser); bus != "" {
				command = F.ToString("env DBUS_SESSION_BUS_ADDRESS='", bus, "' XDG_RUNTIME_DIR=/run/user/", desktopUser.Uid, " ", command)
			}
			return shell.Exec("su", "-", desktopUser.Username, "-c", command).Attach().Run()
		} else {
			return E.New("set system proxy: unable to set as root")
		}
	})
}

// userSessionBus finds the D-Bus session of the desktop user who started this root process: from
// the nearest ancestor that runs as that user (sudo and pkexec are started from the session), else
// from any of the user's processes, else the systemd user bus when something listens on it.
func userSessionBus(desktopUser *user.User) string {
	for pid, steps := os.Getppid(), 0; pid > 1 && steps < 32; steps++ {
		uid, parent := processOwnerAndParent(pid)
		if uid == desktopUser.Uid {
			if bus := processSessionBus(pid); bus != "" {
				return bus
			}
		}
		pid = parent
	}
	if entries, err := os.ReadDir("/proc"); err == nil {
		for _, entry := range entries {
			pid, err := strconv.Atoi(entry.Name())
			if err != nil {
				continue
			}
			if uid, _ := processOwnerAndParent(pid); uid == desktopUser.Uid {
				if bus := processSessionBus(pid); bus != "" {
					return bus
				}
			}
		}
	}
	path := "/run/user/" + desktopUser.Uid + "/bus"
	if conn, err := net.DialTimeout("unix", path, time.Second); err == nil {
		conn.Close()
		return "unix:path=" + path
	}
	return ""
}

func processOwnerAndParent(pid int) (uid string, parent int) {
	content, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/status")
	if err != nil {
		return "", 0
	}
	for _, line := range strings.Split(string(content), "\n") {
		if value, found := strings.CutPrefix(line, "Uid:"); found {
			if fields := strings.Fields(value); len(fields) > 0 {
				uid = fields[0]
			}
		} else if value, found := strings.CutPrefix(line, "PPid:"); found {
			parent, _ = strconv.Atoi(strings.TrimSpace(value))
		}
	}
	return uid, parent
}

func processSessionBus(pid int) string {
	content, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/environ")
	if err != nil {
		return ""
	}
	for _, variable := range strings.Split(string(content), "\x00") {
		if bus, found := strings.CutPrefix(variable, "DBUS_SESSION_BUS_ADDRESS="); found && !strings.ContainsAny(bus, "'\n") {
			return bus
		}
	}
	return ""
}

// invokingUser is the desktop user who started this root process through sudo or pkexec.
func invokingUser() *user.User {
	if name := os.Getenv("SUDO_USER"); name != "" && name != "root" {
		if found, err := user.Lookup(name); err == nil {
			return found
		}
	}
	if uid := os.Getenv("PKEXEC_UID"); uid != "" && uid != "0" {
		if found, err := user.LookupId(uid); err == nil {
			return found
		}
	}
	return nil
}

func NewLinuxSystemProxy(serverAddr M.Socksaddr, supportSOCKS bool, execute func(name string, args ...string) error) (*LinuxSystemProxy, error) {
	hasGSettings := common.Error(exec.LookPath("gsettings")) == nil
	kWriteConfigCmds := []string{
		"kwriteconfig5",
		"kwriteconfig6",
	}
	var kWriteConfigCmd string
	for _, cmd := range kWriteConfigCmds {
		if common.Error(exec.LookPath(cmd)) == nil {
			kWriteConfigCmd = cmd
			break
		}
	}
	if !hasGSettings && kWriteConfigCmd == "" {
		return nil, E.New("unsupported desktop environment")
	}
	return &LinuxSystemProxy{
		execute:         execute,
		hasGSettings:    hasGSettings,
		kWriteConfigCmd: kWriteConfigCmd,
		serverAddr:      serverAddr,
		supportSOCKS:    supportSOCKS,
	}, nil
}

func (p *LinuxSystemProxy) IsEnabled() bool {
	return p.isEnabled
}

func (p *LinuxSystemProxy) Enable() error {
	if p.hasGSettings {
		err := p.execute("gsettings", "set", "org.gnome.system.proxy.http", "enabled", "true")
		if err != nil {
			return err
		}
		if p.supportSOCKS {
			err = p.setGnomeProxy("ftp", "http", "https", "socks")
		} else {
			err = p.setGnomeProxy("http", "https")
		}
		if err != nil {
			return err
		}
		err = p.execute("gsettings", "set", "org.gnome.system.proxy", "use-same-proxy", F.ToString(p.supportSOCKS))
		if err != nil {
			return err
		}
		err = p.execute("gsettings", "set", "org.gnome.system.proxy", "mode", "manual")
		if err != nil {
			return err
		}
	}
	if p.kWriteConfigCmd != "" {
		err := p.execute(p.kWriteConfigCmd, "--file", "kioslaverc", "--group", "Proxy Settings", "--key", "ProxyType", "1")
		if err != nil {
			return err
		}
		if p.supportSOCKS {
			err = p.setKDEProxy("ftp", "http", "https", "socks")
		} else {
			err = p.setKDEProxy("http", "https")
		}
		if err != nil {
			return err
		}
		err = p.execute(p.kWriteConfigCmd, "--file", "kioslaverc", "--group", "Proxy Settings", "--key", "Authmode", "0")
		if err != nil {
			return err
		}
		err = p.execute("dbus-send", "--type=signal", "/KIO/Scheduler", "org.kde.KIO.Scheduler.reparseSlaveConfiguration", "string:''")
		if err != nil {
			return err
		}
	}
	p.isEnabled = true
	return nil
}

func (p *LinuxSystemProxy) Close() error {
	return nil
}

func (p *LinuxSystemProxy) Disable() error {
	if p.hasGSettings {
		err := p.execute("gsettings", "set", "org.gnome.system.proxy", "mode", "none")
		if err != nil {
			return err
		}
	}
	if p.kWriteConfigCmd != "" {
		err := p.execute(p.kWriteConfigCmd, "--file", "kioslaverc", "--group", "Proxy Settings", "--key", "ProxyType", "0")
		if err != nil {
			return err
		}
		err = p.execute("dbus-send", "--type=signal", "/KIO/Scheduler", "org.kde.KIO.Scheduler.reparseSlaveConfiguration", "string:''")
		if err != nil {
			return err
		}
	}
	p.isEnabled = false
	return nil
}

func (p *LinuxSystemProxy) setGnomeProxy(proxyTypes ...string) error {
	for _, proxyType := range proxyTypes {
		err := p.execute("gsettings", "set", "org.gnome.system.proxy."+proxyType, "host", p.serverAddr.AddrString())
		if err != nil {
			return err
		}
		err = p.execute("gsettings", "set", "org.gnome.system.proxy."+proxyType, "port", F.ToString(p.serverAddr.Port))
		if err != nil {
			return err
		}
	}
	return nil
}

func (p *LinuxSystemProxy) setKDEProxy(proxyTypes ...string) error {
	for _, proxyType := range proxyTypes {
		var proxyUrl string
		if proxyType == "socks" {
			proxyUrl = "socks://" + p.serverAddr.String()
		} else {
			proxyUrl = "http://" + p.serverAddr.String()
		}
		err := p.execute(
			p.kWriteConfigCmd,
			"--file",
			"kioslaverc",
			"--group",
			"Proxy Settings",
			"--key", proxyType+"Proxy",
			proxyUrl,
		)
		if err != nil {
			return err
		}
	}
	return nil
}
