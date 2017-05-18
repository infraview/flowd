package main

import (
    "encoding/json"
    "flag"
    "fmt"
    "github.com/google/gopacket"
    "github.com/google/gopacket/layers"
    "github.com/google/gopacket/pcap"
    "io"
    "io/ioutil"
    "net"
    "net/http"
    "os"
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

func runNetworkAnalyzer(networkInterface string, hostIP string, direction string) {
    if handle, err := pcap.OpenLive(networkInterface, 1600, false, -1 * time.Second); err != nil {
        panic(err)
    } else {
        packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
        for packet := range packetSource.Packets() {
            ipLayer := packet.Layer(layers.LayerTypeIPv4)
            tcpLayer := packet.Layer(layers.LayerTypeTCP)

            if ipLayer != nil && tcpLayer != nil {

                ip, _ := ipLayer.(*layers.IPv4)
                tcp, _ := tcpLayer.(*layers.TCP)

                if tcp.DstPort < 32768 && direction == "inbound" && hostIP == ip.SrcIP.String() {

                    srcPort := strconv.Itoa(int(tcp.SrcPort))
                    dstPort := strconv.Itoa(int(tcp.DstPort))

                    srcString := ip.SrcIP.String() + ":" + srcPort
                    dstString := ip.DstIP.String() + ":" + dstPort

                    var found bool = false
                    for _, add := range flowTable.addressList {
                        if add["s"] == srcString && add["d"] == dstString {
                            add["t"] = strconv.FormatInt(time.Now().Unix(), 10)
                            found = true
                        }
                    }

                    if !found {
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
    }
}

func IndexHandler(w http.ResponseWriter, req *http.Request) {
    data, _ := json.Marshal(flowTable.addressList)
    w.Header().Set("Content-Type", "application/json")
    io.WriteString(w, string(data))
}

func main() {
    listenPortArg := flag.String("port", "7777", "Listening port.")
    directionArg := flag.String("direction", "inbound", "Direction of traffic.")
    interfaceArg := flag.String("interface", "eth0", "Network interface to monitor.")

    flag.Parse()

    var hostIP string

    // Get local IP of host
    addrs, err := net.InterfaceAddrs()
    if err != nil {
        os.Stderr.WriteString("Oops: " + err.Error() + "\n")
        os.Exit(1)
    }
    for _, a := range addrs {
        if ipnet, ok := a.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
            if ipnet.IP.To4() != nil {
                hostIP = ipnet.IP.String()
            }
        }
    }

    // Get public IP of host
    response, err := http.Get("http://169.254.169.254/latest/meta-data/public-ipv4")
    if err != nil {
        os.Stderr.WriteString("Failed to fetch public IP: " + err.Error() + "\n")
    }
    defer response.Body.Close()
    res, err := ioutil.ReadAll(response.Body)
    if err != nil {
        os.Stderr.WriteString("Failed to read response: " + err.Error() + "\n")
    }

    fmt.Println("Got public IP: ", string(res))
    fmt.Println("Using host private IP: ", hostIP)

    flowTable = &FlowTable{
        []map[string]string{},
    }

    go runNetworkAnalyzer(*interfaceArg, hostIP, *directionArg)
    http.HandleFunc("/", IndexHandler)
    http.ListenAndServe(":" + *listenPortArg, nil)
}
