package provider

import (
	"context"
	"time"

	"github.com/metacubex/mihomo/common/atomic"
	"github.com/metacubex/mihomo/common/utils"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/log"

	"github.com/metacubex/randv2"
	"golang.org/x/sync/errgroup"
)

const (
	defaultURLTestTimeout = time.Second * 5
	yellowURLTestTimeout  = time.Millisecond * 260
	redURLTestTimeout     = time.Millisecond * 600
	waitAfterAURLTest     = time.Millisecond * 100
)

var (
	healthCheckLazyDefault = true
	touchAfterLazyPassNum  = 0
)

type HealthCheckOption struct {
	URL      string
	Interval uint
}

type HealthCheck struct {
	ctx        context.Context
	ctxCancel  context.CancelFunc
	url        string
	proxies    []C.Proxy
	interval   time.Duration
	lazy       bool
	lastTouch  atomic.TypedValue[time.Time]
	gType      string
	gName      string
	checking   atomic.Bool
	cleanerRun atomic.Bool
}

func (hc *HealthCheck) process() {
	ticker := time.NewTicker(hc.interval)
	passNum := 0

	go hc.lazyCheck()

	for {
		select {
		case <-ticker.C:
			if hc.lazyCheck() {
				passNum = 0
			} else {
				passNum++
				if passNum > 0 && touchAfterLazyPassNum > 0 && passNum > touchAfterLazyPassNum {
					hc.touch()
				}
			}
		case <-hc.ctx.Done():
			ticker.Stop()
			return
		}
	}
}

func (hc *HealthCheck) lazyCheck() bool {
	lastTouch := hc.lastTouch.Load()
	since := time.Since(lastTouch)
	if !hc.lazy || since < hc.interval {
		hc.check()
		return true
	} else {
		log.Debugln("Skip once health check because we are lazy (%s)", hc.gName)
		return false
	}
}

func (hc *HealthCheck) setProxy(proxies []C.Proxy) {
	hc.proxies = proxies
}

func (hc *HealthCheck) auto() bool {
	return hc.interval != 0
}

func (hc *HealthCheck) touch() {
	hc.lastTouch.Store(time.Now())
}

func (hc *HealthCheck) check() {
	if hc.checking.Swap(true) {
		log.Infoln("A Health Checking (%s) is Running, break", hc.gName)
		return
	}
	defer func() {
		hc.checking.Store(false)
	}()
	id := utils.NewUUIDV4().String()
	log.Infoln("Start New Health Checking (%s) {%s}", hc.gName, id)
	switch hc.gType {
	case "fallback":
		hc.fallbackCheck(id)
	default:
		hc.normalCheck(id)
	}
	log.Infoln("Finish A Health Checking (%s) {%s}", hc.gName, id)
}

func (hc *HealthCheck) normalCheck(id string) {
	b := new(errgroup.Group)
	b.SetLimit(10)
	for _, proxy := range hc.proxies {
		p := proxy
		b.Go(func() error {
			ctx, cancel := context.WithTimeout(context.Background(), defaultURLTestTimeout)
			defer cancel()
			log.Infoln("Health Checking (%s) %s {%s}", hc.gName, p.Name(), id)
			p.URLTest(ctx, hc.url)
			log.Infoln("Health Checked (%s) %s : %t %d ms %d ms {%s}", hc.gName, p.Name(), p.Alive(), p.LastDelay(), p.LastMeanDelay(), id)
			return nil
		})
	}
	_ = b.Wait()
}

func (hc *HealthCheck) fallbackCheck(id string) {
	check := func(proxy C.Proxy) {
		ctx, cancel := context.WithTimeout(context.Background(), defaultURLTestTimeout)
		defer cancel()
		log.Infoln("Health Checking (%s) %s {%s}", hc.gName, proxy.Name(), id)
		proxy.URLTest(ctx, hc.url)
		log.Infoln("Health Checked (%s) %s : %t %d ms %d ms {%s}", hc.gName, proxy.Name(), proxy.Alive(), proxy.LastDelay(), proxy.LastMeanDelay(), id)
	}
	wait := func() {
		time.Sleep(waitAfterAURLTest)
	}
	cleaner := func() {
		if hc.cleanerRun.Swap(true) {
			log.Infoln("A Health Check Cleaner (%s) is Running, break", hc.gName)
			return
		}
		defer func() {
			hc.cleanerRun.Store(false)
		}()
		log.Infoln("Start New Health Check Cleaner (%s) {%s}", hc.gName, id)
		b := new(errgroup.Group)
		b.SetLimit(10)
		for _, proxy := range hc.proxies {
			if proxy.Alive() {
				continue
			}
			wait()
			p := proxy
			b.Go(func() error {
				check(p)
				return nil
			})
		}
		_ = b.Wait()
		log.Infoln("Finish A Health Check Cleaner (%s) {%s}", hc.gName, id)
	}
	reds := make([]C.Proxy, 0, len(hc.proxies))
	for _, proxy := range hc.proxies {
		if proxy.Alive() {
			if !ProxyIsRed(proxy) {
				wait()
				check(proxy)
				if proxy.Alive() {
					if !ProxyIsRed(proxy) {
						break
					} else {
						reds = append(reds, proxy)
					}
				}
			} else {
				reds = append(reds, proxy)
			}
		}
	}
	if lenReds := len(reds); lenReds > 0 {
		redProxy := reds[randv2.IntN(lenReds)] // random choose a red proxy to check
		check(redProxy)
	}

	go cleaner()
}

func (hc *HealthCheck) close() {
	hc.ctxCancel()
}

func NewHealthCheck(proxies []C.Proxy, url string, interval uint, lazy bool, gType string, gName string) *HealthCheck {
	if url == "" {
		url = "http://cp.cloudflare.com/generate_204"
	}
	ctx, cancel := context.WithCancel(context.Background())

	return &HealthCheck{
		ctx:       ctx,
		ctxCancel: cancel,
		proxies:   proxies,
		url:       url,
		interval:  time.Duration(interval) * time.Second,
		lazy:      lazy,
		gType:     gType,
		gName:     gName,
	}
}

func HealthCheckLazyDefault() bool {
	return healthCheckLazyDefault
}

func SetHealthCheckLazyDefault(newHealthCheckLazyDefault bool) {
	healthCheckLazyDefault = newHealthCheckLazyDefault
}

func TouchAfterLazyPassNum() int {
	return touchAfterLazyPassNum
}

func SetTouchAfterLazyPassNum(newTouchAfterLazyPassNum int) {
	touchAfterLazyPassNum = newTouchAfterLazyPassNum
}

func proxyIsColor(proxy C.Proxy, timeout time.Duration) bool {
	if timeout == 0 {
		return false
	}
	lastDelay := proxy.LastMeanDelay()
	if lastDelay == 0 || lastDelay == 0xffff {
		return false
	}
	return lastDelay >= uint16(timeout/time.Millisecond)
}

func ProxyIsYellow(proxy C.Proxy) bool {
	return proxyIsColor(proxy, yellowURLTestTimeout)
}

func ProxyIsRed(proxy C.Proxy) bool {
	return proxyIsColor(proxy, redURLTestTimeout)
}
