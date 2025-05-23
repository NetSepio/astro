package core

import (
	"fmt"
	"math/rand"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/NetSepio/astro/api/v1/service/util"
)

// var AppConfDir = "./conf"
var CaddyJSON = "caddy.json"

// WG_CONF_DIR
var CaddyConfDir = os.Getenv("WG_CONF_DIR")
var CaddyFile = os.Getenv("CADDY_INTERFACE_NAME")

// Init initializes json file for caddy
func Init() {
	//caddy.json path
	wd, err := os.Getwd()
	if err != nil {
		fmt.Println("\n🚨 Error:", err)
	} else {
		fmt.Println("\n✅ Current Working Directory:", wd)
	}
	fmt.Println("\n📂 Current Path:", wd)

	path := filepath.Join(os.Getenv("SERVICE_CONF_DIR"), CaddyJSON)
	//check if exists
	if !util.FileExists(path) {
		err := util.CreateJSONFile(path)
		if err != nil {
			util.CheckError("caddy.json error: ", err)
		}
	}
}

// Writefile appends data to file
func Writefile(path string, bytes []byte) (err error) {
	file, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		util.LogError("File Open error: ", err)
		return err
	}

	defer file.Close()

	_, err = file.WriteString(string(bytes))
	if err != nil {
		util.LogError("File write error: ", err)
		return err
	}

	return nil
}

// ScanPort checks avilability of port
func ScanPort(port int) (string, error) {
	ip := os.Getenv("SERVER")
	timer := 500 * time.Millisecond

	target := fmt.Sprintf("%s:%d", ip, port)
	conn, err := net.DialTimeout("tcp", target, timer)

	if err != nil {
		if strings.Contains(err.Error(), "too many open files") {
			time.Sleep(timer)
			ScanPort(port)
		} else {
			return "inactive", nil
		}
		return "", err
	}

	conn.Close()
	return "active", nil
}

// GetPort returns available port based on random generation
func GetPort(max, min int) (int, error) {
	port := rand.Intn(max-min) + min

	status, err := ScanPort(port)
	if err != nil {
		util.LogError("Scan Port error: ", err)
		return -1, err
	}

	if status == "inactive" {
		return port, nil
	} else if status == "active" {
		GetPort(max, min)
	}

	return -1, nil
}
