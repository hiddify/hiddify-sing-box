package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net"
	"os"
	"strings"

	_ "embed"

	"github.com/oschwald/geoip2-golang"
)

//go:embed resolvers.txt
var resolvers string

func main() {
	db, err := geoip2.Open("GeoLite2-Country.mmdb")
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()
	added := map[string]struct{}{}
	result := map[string][]string{}
	for _, line := range strings.Split(resolvers, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || line[0] == '#' {
			continue
		}

		ip := net.ParseIP(line)
		record, err := db.Country(ip)
		if err != nil {
			continue
		}
		country := record.Country.IsoCode
		if _, ok := added[line]; !ok {
			result[country] = append(result[country], line)
			added[line] = struct{}{}
		}
	}

	j, _ := json.MarshalIndent(result, "", "  ")
	fmt.Println(string(j))

	os.WriteFile("ips_by_country.json", j, 0644)

}
