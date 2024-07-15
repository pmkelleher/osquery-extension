package tetherator

import (
	"context"
	"fmt"

	"github.com/osquery/osquery-go/plugin/table"
)

func TetheratorRosterColumns() []table.ColumnDefinition {
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

func marshalTetheratorRoster(status Status) []map[string]string {
	var results []map[string]string

	for _, device := range status.Result.DeviceRoster {
		results = append(results, map[string]string{
			"name":              device.Name,
			"serial_number":     device.SerialNumber,
			"bridged":           fmt.Sprintf("%d", BoolToInt(device.Bridged)),
			"check_in_attempts": fmt.Sprintf("%d", device.CheckInAttempts),
			"check_in_pending":  fmt.Sprintf("%d", BoolToInt(device.CheckInPending)),
			"checked_in":        fmt.Sprintf("%d", BoolToInt(device.CheckedIn)),
			"location_id":       fmt.Sprintf("%d", device.LocationID),
			"paired":            fmt.Sprintf("%d", BoolToInt(device.Paired)),
		})
	}
	return results
}

func TetheratorRosterGenerate(ctx context.Context, queryContext table.QueryContext) ([]map[string]string, error) {
	var results []map[string]string
	cmdExecutor := CmdExecutor{}
	status, err := getTetheratorStatus(cmdExecutor)
	if err != nil {
		fmt.Println(err)
		return results, err
	}

	results = marshalTetheratorRoster(status)

	return results, nil
}
