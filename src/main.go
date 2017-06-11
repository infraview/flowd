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
    "sort"
    "strconv"
    "time"
)

type Interface interface {
    Len() int
    Less(i, j int) bool
    Swap(i, j int)
}

type int64Array []int64
func (s int64Array) Len() int { return len(s) }
func (s int64Array) Swap(i, j int) { s[i], s[j] = s[j], s[i] }
func (s int64Array) Less(i, j int) bool { return s[i] > s[j] }


type FlowTable struct {
    addressList []map[string]string
}

type FlowTimeline struct {
    timeline map[int64]FlowTable
}

var flowTable FlowTable
var flowTimeline *FlowTimeline

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

                // Save timestamps
                var keys []int64
                for k := range flowTimeline.timeline {
                    keys = append(keys, k)
                }
                // Sort timestamps in reverse
                sort.Sort(int64Array(keys))

                // Find current timestamp
                currentTimestamp := time.Now().Unix()
                for _, ts := range keys {
                    if ts <= currentTimestamp {
                      currentTimestamp = ts
                      break
                    }
                }

                if tcp.DstPort < 32768 && direction == "outbound" && hostIP == ip.SrcIP.String() {

                    srcPort := strconv.Itoa(int(tcp.SrcPort))
                    dstPort := strconv.Itoa(int(tcp.DstPort))

                    srcString := ip.SrcIP.String() + ":" + srcPort
                    dstString := ip.DstIP.String() + ":" + dstPort

                    var found bool = false
                    for _, add := range flowTimeline.timeline[currentTimestamp].addressList {
                        if add["d"] == dstString {
                            count, err := strconv.Atoi(add["c"])
                            if err != nil {
                                os.Stderr.WriteString("Oops: " + err.Error() + "\n")
                            }

                            add["t"] = strconv.FormatInt(time.Now().Unix(), 10)
                            add["c"] = strconv.Itoa(count + 1)
                            found = true
                        }
                    }

                    if !found {
                        conn := map[string]string{
                            "t": strconv.FormatInt(time.Now().Unix(), 10),
                            "s": srcString,
                            "d": dstString,
                            "c": "1",
                        }
                        // Avoid direct assignment to map key by using
                        // a temp FlowTable
                        var tempFlowTable FlowTable
                        tempFlowTable = flowTimeline.timeline[currentTimestamp]
                        tempFlowTable.addressList = Append(tempFlowTable.addressList, conn)
                        flowTimeline.timeline[currentTimestamp] = tempFlowTable
                    }
                }
            }
        }
    }
}

func runManager(refreshTime string, keepCount string) {
  // Convert keepCount
  keepCountVal, err := strconv.Atoi(keepCount)
  if err != nil {
      os.Stderr.WriteString("Oops: " + err.Error() + "\n")
  }

  // Convert refreshTime
  refreshTimeVal, err := strconv.ParseInt(refreshTime, 10, 64)
  if err != nil {
      os.Stderr.WriteString("Oops: " + err.Error() + "\n")
  }

  // Init timeline struct with current timestamp and next one
  timeNow := time.Now().Unix()
  timeNext := timeNow + refreshTimeVal

  // Init timeline struct
  flowTimeline = &FlowTimeline{
    timeline: map[int64]FlowTable{
      timeNow: FlowTable{},
      timeNext: FlowTable{},
    },
  }

  // Convert refreshTime to int
  rtime, err := strconv.Atoi(refreshTime)
  if err != nil {
      os.Stderr.WriteString("Oops: " + err.Error() + "\n")
  }

  // Start ticker
  ticker := time.NewTicker(time.Second * time.Duration(rtime))
  for _ = range ticker.C {
    // Remove oldest timestamp if expired
    if len(flowTimeline.timeline) >= keepCountVal {
      delete(flowTimeline.timeline, timeNow)
      timeNow = timeNow + refreshTimeVal
    }

    // Add timestamp if needed
    if len(flowTimeline.timeline) < keepCountVal {
      timeNext = timeNext + refreshTimeVal
      flowTimeline.timeline[timeNext] = FlowTable{}
    }
  }
}

func IndexHandler(w http.ResponseWriter, req *http.Request) {
    var response map[string][]map[string]string
    response = make(map[string][]map[string]string)

    // Build JSON response
    for k := range flowTimeline.timeline {
        response[strconv.FormatInt(k, 10)] = make([]map[string]string, len(flowTimeline.timeline[k].addressList))
        response[strconv.FormatInt(k, 10)] = flowTimeline.timeline[k].addressList
    }

    // Convert to JSON
    data, err := json.Marshal(response)
    if err != nil {
        os.Stderr.WriteString("Failed parse timeline: " + err.Error() + "\n")
    }

    // Send response
    w.Header().Set("Content-Type", "application/json")
    io.WriteString(w, string(data))
}

func main() {
    listenPortArg := flag.String("port", "7777", "Listening port.")
    directionArg := flag.String("direction", "outbound", "Direction of traffic.")
    interfaceArg := flag.String("interface", "eth0", "Network interface to monitor.")

    refreshTimeArg := flag.String("refreshTime", "5", "Refresh time in seconds.")
    keepCountArg := flag.String("keepCount", "5", "Number of timeintervals to keep.")

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

    flowTable = FlowTable{
        []map[string]string{},
    }

    // Start Manager
    go runManager(*refreshTimeArg, *keepCountArg)

    // Start Network Analyzer
    go runNetworkAnalyzer(*interfaceArg, hostIP, *directionArg)

    // Start Web Server
    http.HandleFunc("/", IndexHandler)
    http.ListenAndServe(":" + *listenPortArg, nil)
}
