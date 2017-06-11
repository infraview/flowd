# flowd

Project forked from: https://github.com/tadasv/flowd
It works with: https://github.com/mariuscoto/infraview

Flowd is a simple network monitoring service. It captures TCP/IP traffic and keeps track of
`source -> destination` mappings, which are exposed via HTTP server running on port `7777`.

Sample output:

```json
{
  "1497169646": null,
  "1497169651": null,
  "1497169656": [
    {
      "c": "2",
      "d": "8.8.8.8:56",
      "s": "172.31.46.139:37316",
      "t": "1497169659"
    }
  ],
  "1497169661": [
    {
      "c": "1",
      "d": "8.8.8.8:70",
      "s": "172.31.46.139:43844",
      "t": "1497169661"
    }
  ],
  "1497169666": null
}
```

## Build

`go build src/main.go`

## Run

`go run src/main.go`
