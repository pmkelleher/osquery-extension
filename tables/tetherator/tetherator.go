package tetherator

import (
	"context"
	"encoding/json"
	"fmt"
	"os/exec"

	"github.com/osquery/osquery-go/plugin/table"
	"github.com/pkg/errors"
)

type Status struct {
	Name   string `json:"name"`
	Result Result `json:"result"`
}

type Result struct {
	Active           bool             `json:"Active"`
	DeviceRoster     []Device         `json:"Device Roster"`
	PrimaryInterface PrimaryInterface `json:"Primary Interface"`
	Standalone       bool             `json:"Standalone"`
}

type Device struct {
	Bridged         bool   `json:"Bridged"`
	CheckInAttempts int    `json:"Check In Attempts"`
	CheckInPending  bool   `json:"Check In Pending"`
	CheckedIn       bool   `json:"Checked In"`
	LocationID      int    `json:"Location ID"`
	Name            string `json:"Name"`
	Paired          bool   `json:"Paired"`
	SerialNumber    string `json:"Serial Number"`
}

type PrimaryInterface struct {
	BSDName      string `json:"BSD Name"`
	IPAddress    string `json:"IP Address"`
	Mbps         int    `json:"Mbps"`
	UserReadable string `json:"User Readable"`
	Wired        bool   `json:"Wired"`
}

func DevicesColumns() []table.ColumnDefinition {
	return []table.ColumnDefinition{
		table.TextColumn("name"),
		table.TextColumn("serial_number"),
		table.IntegerColumn("bridged"),
		table.IntegerColumn("check_in_attempts"),
		table.IntegerColumn("check_in_pending"),
		table.IntegerColumn("checked_in"),
		table.IntegerColumn("location_id"),
		table.IntegerColumn("paired"),
	}
}

// Generate will be called whenever the table is queried. Since our data in these
// plugins is flat it will return a single row.
func DevicesGenerate(ctx context.Context, queryContext table.QueryContext) ([]map[string]string, error) {
	var results []map[string]string
	devices, err := getTetheratorDevices()
	if err != nil {
		fmt.Println(err)
		return results, err
	}

	for _, device := range devices {
		results = append(results, map[string]string{
			"name":              device.Name,
			"serial_number":     device.SerialNumber,
			"bridged":           fmt.Sprintf("%d", boolToInt(device.Bridged)),
			"check_in_attempts": fmt.Sprintf("%d", device.CheckInAttempts),
			"check_in_pending":  fmt.Sprintf("%d", boolToInt(device.CheckInPending)),
			"checked_in":        fmt.Sprintf("%d", boolToInt(device.CheckedIn)),
			"location_id":       fmt.Sprintf("%d", device.LocationID),
			"paired":            fmt.Sprintf("%d", boolToInt(device.Paired)),
		})
	}

	return results, nil
}

func getTetheratorDevices() ([]Device, error) {
	var devices []Device

	bytes, err := runAssetCacheTetheratorStatus()
	if err != nil {
		return devices, errors.Wrap(err, "runAssetCacheTetheratorStatus")
	}

	status, err := processTetheratorStatus(bytes)
	if err != nil {
		return devices, errors.Wrap(err, "processTetheratorStatus")
	}

	return status.Result.DeviceRoster, nil
}

func runAssetCacheTetheratorStatus() ([]byte, error) {
	out, err := exec.Command("/usr/bin/assetCacheTetheratorUtil", "-j", "status").Output()
	if err != nil {
		return out, errors.Wrap(err, "assetCacheTetheratorUtil -j status")
	}
	return out, nil
}

func processTetheratorStatus(bytes []byte) (Status, error) {
	var status Status
	err := json.Unmarshal(bytes, &status)
	if err != nil {
		return status, errors.Wrap(err, "json.Unmarshal")
	}

	return status, nil
}

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}
