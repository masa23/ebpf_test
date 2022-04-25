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
	XdpProg *ebpf.Program `ebpf:"xdp_prog"`
	XdpMap  *ebpf.Map     `ebpf:"xdp_map"`
}

func main() {
	var iface string = "enp1s0"
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)

	link, err := netlink.LinkByName(iface)
	if err != nil {
		panic(err)
	}

	objs := xdpObjects{}
	if err := loadXdpObjects(&objs, nil); err != nil {
		panic(err)
	}
	defer objs.Close()

	if err := netlink.LinkSetXdpFd(link, objs.XdpProg.FD()); err != nil {
		panic(err)
	}

	count := make([]byte, 4)
	go func() {
		for {
			m := objs.xdpMaps.XdpMap
			pp.Println(m)
			err := m.Lookup(uint32(1), &count)
			pp.Println(err, count)
			time.Sleep(time.Second)
		}
	}()

	<-sig
	/*
		if err := os.RemoveAll(tmpdir); err != nil {
			panic(err)
		}*/
	if err := netlink.LinkSetXdpFd(link, -1); err != nil {
		panic(err)
	}
}
