//go:build amd64 && linux
// +build amd64,linux

package main

import (
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
	"github.com/k0kubun/pp"
	"github.com/vishvananda/netlink"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -target bpf xdp ./src/xdp.c -- -I./include -Wno-unused-value -Wno-pointer-sign -Wno-compare-distinct-pointer-types -Wnull-character -g -c -O2 -D__KERNEL__

type Collect struct {
	XdpProg *ebpf.Program `ebpf:"prog"`
	//	XdpcapHook *ebpf.Map     `ebpf:"xdpcap_hook"`
}

func main() {
	var iface string = "enp1s0"
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)

	link, err := netlink.LinkByName(iface)
	if err != nil {
		panic(err)
	}

	xdp, err := loadXdp()
	if err != nil {
		panic(err)
	}
	collect := &Collect{}
	if err := xdp.LoadAndAssign(collect, nil); err != nil {
		panic(err)
	}
	if err := netlink.LinkSetXdpFd(link, collect.XdpProg.FD()); err != nil {
		panic(err)
	}
	/*	tmpDir := "/sys/fs/bpf/xdp"
		if err := collect.XdpcapHook.Pin(tmpDir); err != nil {
			panic(err)
		}*/

	go func() {
		for {
			pp.Println(xdp)
			time.Sleep(time.Second)
		}
	}()

	<-sig
	/*if err := os.RemoveAll(tmpDir); err != nil {
		panic(err)
	}*/
	if err := netlink.LinkSetXdpFd(link, -1); err != nil {
		panic(err)
	}
}
