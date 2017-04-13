package main

import (
	"encoding/json"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"io"
	"net/http"
	"strconv"
	"time"
)

type FlowTable struct {
	addressList []map[string]string
}


var flowTable *FlowTable

func Extend(slice []map[string]string, element map[string]string) []map[string]string {
    n := len(slice)
    if n == cap(slice) {
        // Slice is full; must grow.
        // We double its size and add 1, so if the size is zero we still grow.
        newSlice := make([]map[string]string, len(slice), 2*len(slice)+1)
        copy(newSlice, slice)
        slice = newSlice
    }
    slice = slice[0 : n+1]
    slice[n] = element
    return slice
}


// Append appends the items to the slice.
// First version: just loop calling Extend.
func Append(slice []map[string]string, items ...map[string]string) []map[string]string {
    for _, item := range items {
        slice = Extend(slice, item)
    }
    return slice
}

func runNetworkAnalyzer(networkInterface string) {
	if handle, err := pcap.OpenLive(networkInterface, 1600, true, pcap.BlockForever); err != nil {
		panic(err)
	} else {
		packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
		for packet := range packetSource.Packets() {
			ipLayer := packet.Layer(layers.LayerTypeIPv4)
			tcpLayer := packet.Layer(layers.LayerTypeTCP)

			if ipLayer != nil && tcpLayer != nil {
				ip, _ := ipLayer.(*layers.IPv4)
				tcp, _ := tcpLayer.(*layers.TCP)

				srcPort := strconv.Itoa(int(tcp.SrcPort))
				dstPort := strconv.Itoa(int(tcp.DstPort))

				srcString := ip.SrcIP.String() + ":" + srcPort
				dstString := ip.DstIP.String() + ":" + dstPort

				conn := map[string]string{
					"t": strconv.FormatInt(time.Now().Unix(), 10),
					"s": srcString,
					"d": dstString,
				}
				flowTable.addressList = Append(flowTable.addressList, conn)
			}
		}
	}
}

func IndexHandler(w http.ResponseWriter, req *http.Request) {
	data, _ := json.Marshal(flowTable.addressList)
	w.Header().Set("Content-Type", "application/json")
	io.WriteString(w, string(data))
}

func main() {
	flowTable = &FlowTable{
		[]map[string]string{},
	}

	go runNetworkAnalyzer("eth0")
	http.HandleFunc("/", IndexHandler)
	http.ListenAndServe(":7777", nil)
}
