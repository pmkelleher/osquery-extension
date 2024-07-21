package cfgutil

import (
	"context"
	"fmt"

	"github.com/osquery/osquery-go/plugin/table"
)

func CfgutilListColumns() []table.ColumnDefinition {
	return []table.ColumnDefinition{
		table.IntegerColumn("location_id"),
		table.TextColumn("udid"),
		table.TextColumn("ecid"),
		table.TextColumn("name"),
		table.TextColumn("device_type"),
	}
}

func marshalCfgutilList(commandOutput CommandOutput) []map[string]string {
	var results []map[string]string

	for _, device := range commandOutput.Output {
		results = append(results, map[string]string{
			"location_id": fmt.Sprintf("%d", device.LocationID),
			"udid":        device.UDID,
			"ecid":        device.ECID,
			"name":        device.Name,
			"device_type": device.DeviceType,
		})
	}
	return results
}

func CfgutilListGenerate(ctx context.Context, queryContext table.QueryContext) ([]map[string]string, error) {
	var results []map[string]string
	cmdExecutor := CmdExecutor{}
	status, err := getCommandOutput(cmdExecutor)
	if err != nil {
		fmt.Println(err)
		return results, err
	}

	results = marshalCfgutilList(status)

	return results, nil
}
