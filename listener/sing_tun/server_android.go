//go:build android && !cmfa

package sing_tun

import (
	"sync"

	"github.com/metacubex/mihomo/log"

	"github.com/metacubex/sing-tun"
)

type packageManagerCallback struct{}

func (cb *packageManagerCallback) OnPackagesUpdated(packageCount int, sharedCount int) {}

func newPackageManager() (tun.PackageManager, error) {
	packageManager, err := tun.NewPackageManager(tun.PackageManagerOptions{
		Callback: &packageManagerCallback{},
		Logger:   log.SingLogger,
	})
	if err != nil {
		return nil, err
	}
	err = packageManager.Start()
	if err != nil {
		return nil, err
	}
	return packageManager, nil
}

var (
	globalPM tun.PackageManager
	pmOnce   sync.Once
	pmErr    error
)

func getPackageManager() (tun.PackageManager, error) {
	pmOnce.Do(func() {
		globalPM, pmErr = newPackageManager()
	})
	return globalPM, pmErr
}

func (l *Listener) buildAndroidRules(tunOptions *tun.Options) error {
	packageManager, err := getPackageManager()
	if err != nil {
		return err
	}
	tunOptions.BuildAndroidRules(packageManager, l.handler)
	return nil
}
