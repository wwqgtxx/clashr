package config

import (
	"fmt"
	"io"
	"os"

	"github.com/metacubex/mihomo/component/mmdb"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/log"

	"github.com/metacubex/http"
)

func downloadMMDB(path string) (err error) {
	resp, err := http.Get("https://cdn.jsdelivr.net/gh/Loyalsoldier/geoip@release/Country.mmdb")
	if err != nil {
		return
	}
	defer resp.Body.Close()

	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = io.Copy(f, resp.Body)

	return err
}

func initMMDB() error {
	C.SetExtraMMDB(true)
	if _, err := os.Stat(C.Path.MMDB()); os.IsNotExist(err) {
		if len(mmdb.EmbedMMDB) > 0 {
			log.Infoln("Can't find MMDB file, use embed MMDB")
			C.SetExtraMMDB(false)
		} else {
			log.Infoln("Can't find MMDB, start download")
			if err := downloadMMDB(C.Path.MMDB()); err != nil {
				return fmt.Errorf("can't download MMDB: %s", err.Error())
			}
		}
	}

	if !mmdb.Verify() {
		if len(mmdb.EmbedMMDB) > 0 {
			log.Warnln("MMDB invalid, use embed MMDB")
			C.SetExtraMMDB(false)
		} else {
			log.Warnln("MMDB invalid, remove and download")
			if err := os.Remove(C.Path.MMDB()); err != nil {
				return fmt.Errorf("can't remove invalid MMDB: %s", err.Error())
			}

			if err := downloadMMDB(C.Path.MMDB()); err != nil {
				return fmt.Errorf("can't download MMDB: %s", err.Error())
			}
		}
	}

	return nil
}

// Init prepare necessary files
func Init(dir string) error {
	// initial homedir
	if _, err := os.Stat(dir); os.IsNotExist(err) {
		if err := os.MkdirAll(dir, 0o777); err != nil {
			return fmt.Errorf("can't create config directory %s: %s", dir, err.Error())
		}
	}

	// initial config.yaml
	if _, err := os.Stat(C.Path.Config()); os.IsNotExist(err) {
		log.Infoln("Can't find config, create a initial config file")
		f, err := os.OpenFile(C.Path.Config(), os.O_CREATE|os.O_WRONLY, 0o644)
		if err != nil {
			return fmt.Errorf("can't create file %s: %s", C.Path.Config(), err.Error())
		}
		f.Write([]byte(`mixed-port: 7890`))
		f.Close()
	}

	// initial mmdb
	if err := initMMDB(); err != nil {
		return fmt.Errorf("can't initial MMDB: %w", err)
	}
	return nil
}
