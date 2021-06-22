// Copyright 2021 The SucuriAPI AUTHORS. All rights reserved.
//
// Use of this source code is governed by an MIT License
// license that can be found in the LICENSE file.

/* !!! TODO Rework how whitelist IPs and other varibles are stored before processing them.
The call to whitelist IPs shouldn't be done twice.
Better method is to assing the data either from the command line or config and store to a variable and process whatever is assinged to the variable
The above eliminates to needing to change processes twice, once for standalone second for template.
*/
// !!! TODO Rework Whitelisting path simmilarly to whitlisting IPs
// !!  TODO Add support to whitelist subnet
// !!  TODO Add Support for blacklisting path and IP
// !   TODO Add Support to add/remove site

package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/ZsoltFejes/SucuriAPI-Go"
)

type Template struct {
	WhitelistIP   []string          `json:"whitelistIPs,omitempty"`
	WhitelistPath map[string]string `json:"whitelistPaths,omitempty"`
	Settings      map[string]string `json:"settings,omitempty"`
}

type ConfigFile struct {
	ApiKey string            `json:"apiKey,omitempty"`
	Sites  map[string]string `json:"sites,omitempty"`
}

func submitRequest(request SucuriAPI.SucuriRequest, wg *sync.WaitGroup) {
	request.Submit()
	wg.Done()
}

func whitelistIPs(IPs []string, delete bool, sucuri *SucuriAPI.Sucuri) []SucuriAPI.SucuriRequest {
	var requests []SucuriAPI.SucuriRequest
	for _, ip := range IPs {
		requests = append(requests, sucuri.WhitelistIP(ip, delete))
	}
	return requests
}

func main() {
	apiKey := flag.String("key", "", "Sucuri API Key for the site")
	apiSecret := flag.String("secret", "", "Sucuri API Secret for the site")
	whitelistIP := flag.String("whitelistIP", "", "Whitelist IP, or multiple IPs, example 200.0.0.1 or 200.0.0.1,200.0.0.10,200.0.0.175")
	whitelistSubnet := flag.String("whitelistSubnet", "", "Whitelist Subnet(s), example 200.0.0.0/27 or 200.0.0.0/27,200.0.1.0/30")
	delete := flag.Bool("delete", false, "Use flag to remove entries, (Settings can't be removed only whitelisted/blacklisted entries)")
	templatePath := flag.String("template", "", "Set path to tempalte and apply all specified settings, whitelists and blacklists")
	site := flag.String("site", "", "If you store the apiKey and sites in api.json file specify which site you want to apply changes")
	flag.Parse()

	sucuri := SucuriAPI.Sucuri{
		Url: "https://waf.sucuri.net/api?v2",
	}

	// Variables for config
	ex, err := os.Executable()
	if err != nil {
		panic(err)
	}
	workdir := filepath.Dir(ex)
	configFile := ConfigFile{}
	configFilePath := workdir + "/config.json"
	// Check if config file 'config.json' exist in the same directory as the executable
	if _, err := os.Stat(configFilePath); !os.IsNotExist(err) {
		file, _ := os.ReadFile(configFilePath)
		err = json.Unmarshal(file, &configFile)
		if err != nil {
			fmt.Printf("Unable to parse config file, please check the content and refer to the documentation. \n%s\n\n", err)
			os.Exit(2)
		}
	}

	// Load apiKey to sucuri
	if len(*apiKey) == 0 {
		if len(configFile.ApiKey) > 0 {
			sucuri.ApiKey = configFile.ApiKey
		} else {
			fmt.Println(`API Key wasn't provided, and it was not found in config file. (use --key '<key>', or add "apiKey": "<apiKey>" to config file)`)
			os.Exit(2)
		}
	} else {
		sucuri.ApiKey = *apiKey
	}

	// Load apiSecret to sucuri
	if len(*apiSecret) == 0 && len(*site) > 0 {
		// Check if site exist
		if len(configFile.Sites[*site]) > 0 {
			sucuri.ApiSecret = configFile.Sites[*site]
		} else {
			fmt.Printf("Site '%s' not found in config file", *site)
			os.Exit(2)
		}
		// If apiSecret was specified but not site
	} else if len(*apiSecret) > 0 && len(*site) == 0 {
		sucuri.ApiSecret = *apiSecret
	} else if len(*apiSecret) == 0 && len(*site) == 0 {
		fmt.Println("No apiSecret or site was provided")
		os.Exit(2)
	} else if len(*apiSecret) > 0 && len(*site) > 0 {
		fmt.Println("Only use --secret or --site, not both")
		os.Exit(2)
	}

	var (
		requests []SucuriAPI.SucuriRequest
		wg       sync.WaitGroup
	)

	// ############################## TODO Rework after this comment ##############################

	if len(*whitelistIP) > 0 {
		ips := strings.Split(*whitelistIP, ",")
		requests = append(requests, whitelistIPs(ips, *delete, &sucuri)...)
	}
	if len(*whitelistSubnet) > 0 {
		fmt.Println("Whitlisting subnet is not supported yet")
	}
	if len(*templatePath) > 0 {
		template := Template{Settings: make(map[string]string), WhitelistPath: make(map[string]string)}

		file, err := ioutil.ReadFile(*templatePath)
		if err != nil {
			fmt.Println("Check the template file if it exist.")
			os.Exit(2)
		}

		err = json.Unmarshal(file, &template)
		if err != nil {
			fmt.Println("Unable to parse template file, please check the content and refer to the documentation.")
			os.Exit(2)
		}

		// Create sucuriRequest for all IPs to be whitelisted
		if len(template.WhitelistIP) > 0 {
			requests = append(requests, whitelistIPs(template.WhitelistIP, false, &sucuri)...)
		}

		// Create sucuriRequest for all url paths to be whitelisted
		if len(template.WhitelistPath) > 0 {
			for path, pattern := range template.WhitelistPath {
				requests = append(requests, sucuri.WhitelistPath(path, pattern))
			}
		}

		// Create sucuriRequest for each setting change
		if len(template.Settings) > 0 {
			for key, value := range template.Settings {
				requests = append(requests, sucuri.UpdateSetting(key, value))
			}
		}

		// Process all Sucuri Requests
		for _, request := range requests {
			wg.Add(1)
			go submitRequest(request, &wg)
		}
		wg.Wait()
	}
}
