# flowd

Project forked from: https://github.com/tadasv/flowd
It works with: https://github.com/mariuscoto/infraview

Flowd is a simple network monitoring service. It captures TCP/IP traffic and keeps track of
`source -> destination` mappings, which are exposed via HTTP server running on port `7777`.

Sample output:

```json
[
  {
    "d": "91.189.88.149:80",
    "s": "172.31.46.139:59938",
    "t": "1497168807"
  },
  {
    "d": "54.205.195.154:80",
    "s": "172.31.46.139:47796",
    "t": "1497168807"
  },
  {
    "d": "54.198.110.211:80",
    "s": "172.31.46.139:33296",
    "t": "1497168818"
  },
  {
    "d": "91.189.95.15:80",
    "s": "172.31.46.139:52106",
    "t": "1497168863"
  }
]
```

## Build

`go build src/main.go`

## Run

`go run src/main.go`
