//go:build linux
// +build linux

package main

import (
	"encoding/binary"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
	"github.com/dustin/go-humanize"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -target bpf tc ./src/tc.c -- -I../include -Wno-unused-value -Wno-pointer-sign -Wno-compare-distinct-pointer-types -Wnull-character -g -c -O2 -D__KERNEL__

type Collect struct {
	XdpProg *ebpf.Program `ebpf:"tc_prog"`
	XdpMap  *ebpf.Map     `ebpf:"tc_map"`
}

func main() {
	var iface string
	flag.StringVar(&iface, "iface", "enp1s0", "summrize interface")
	flag.Parse()

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)

	link, err := netlink.LinkByName(iface)
	if err != nil {
		panic(err)
	}

	attrs := netlink.QdiscAttrs{
		LinkIndex: link.Attrs().Index,
		Handle:    netlink.MakeHandle(0xffff, 0),
		Parent:    netlink.HANDLE_CLSACT,
	}

	qdisc := &netlink.GenericQdisc{
		QdiscAttrs: attrs,
		QdiscType:  "ingress",
	}

	objs := tcObjects{}
	if err := loadTcObjects(&objs, nil); err != nil {
		panic(err)
	}
	defer objs.Close()

	progFd := objs.tcPrograms.Tc.FD()

	if err := netlink.QdiscAdd(qdisc); err != nil {
		log.Fatalf("cannot add clsact qdisc: %v", err)
	}

	filterAttrs := netlink.FilterAttrs{
		LinkIndex: link.Attrs().Index,
		Parent:    netlink.HANDLE_MIN_INGRESS,
		Handle:    netlink.MakeHandle(0, 1),
		Protocol:  unix.ETH_P_ALL,
		Priority:  1,
	}

	filter := &netlink.BpfFilter{
		FilterAttrs:  filterAttrs,
		Fd:           progFd,
		Name:         "hi-tc",
		DirectAction: true,
	}

	if err := netlink.FilterAdd(filter); err != nil {
		log.Fatalf("cannot attach bpf object to filter: %v", err)
	}

	go func() {
		for {
			var key uint32
			var count uint64
			m := objs.tcMaps.TcMap
			err := m.NextKey(nil, &key)
			if err != nil {
				time.Sleep(time.Second)
				continue
			}
			for i := 0; i <= int(m.MaxEntries()); i++ {
				err = m.Lookup(key, &count)
				if err != nil {
					fmt.Printf("count: %d\n", i+1)
					break
				}
				ipaddr := make(net.IP, 4)
				binary.LittleEndian.PutUint32(ipaddr, key)
				fmt.Printf("IP: %s\t%s\n", ipaddr.String(), humanize.Bytes(count))
				oldKey := key
				err := m.NextKey(oldKey, &key)
				if err != nil {
					fmt.Printf("count: %d\n", i+1)
					time.Sleep(time.Second)
					break
				}
			}

			list, _ := mapKeyList(m)
			for _, v := range list {
				key := v.(uint32)
				ipaddr := make(net.IP, 4)
				binary.LittleEndian.PutUint32(ipaddr, key)
				//pp.Println(ipaddr.String())
				//m.Delete(key)
			}
			//pp.Println(list, err)

			time.Sleep(time.Second)
		}
	}()

	<-sig
	netlink.FilterDel(filter)
	netlink.QdiscDel(qdisc)
}

func mapKeyList(m *ebpf.Map) (keys []interface{}, err error) {
	var key, oldKey uint32
	err = m.NextKey(nil, &oldKey)
	if err != nil {
		return keys, err
	}
	keys = append(keys, oldKey)
	for i := 0; i <= int(m.MaxEntries()); i++ {
		err = m.NextKey(oldKey, &key)
		if err != nil {
			break
		}
		keys = append(keys, key)
		oldKey = key
	}

	return keys, nil
}
