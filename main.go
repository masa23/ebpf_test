//go:build linux
// +build linux

package main

import (
	"encoding/binary"
	"net"
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

	go func() {
		for {
			/*
				var count uint32
				m := objs.xdpMaps.XdpMap
				m.Lookup(uint32(1), &count)
				pp.Println(count)
				m.Delete(uint32(1))
				pp.Println(err)
				pp.Println(m)
			*/
			var key uint32
			var count uint32
			m := objs.xdpMaps.XdpMap
			err := m.NextKey(nil, &key)
			if err != nil {
				time.Sleep(time.Second)
				continue
			}
			for i := 0; i <= int(m.MaxEntries()); i++ {
				err = m.Lookup(key, &count)
				if err != nil {
					break
				}
				ipaddr := make(net.IP, 4)
				binary.LittleEndian.PutUint32(ipaddr, key)
				pp.Println(ipaddr.String(), count)
				oldKey := key
				err := m.NextKey(oldKey, &key)
				if err != nil {
					time.Sleep(time.Second)
					break
				}
			}

			time.Sleep(time.Second)
		}
	}()

	<-sig
	if err := netlink.LinkSetXdpFd(link, -1); err != nil {
		panic(err)
	}
}
