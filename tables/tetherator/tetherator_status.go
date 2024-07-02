package tetherator

import (
	"context"
	"fmt"

	"github.com/osquery/osquery-go/plugin/table"
)

func TetheratorStatusColumns() []table.ColumnDefinition {
	return []table.ColumnDefinition{
		table.IntegerColumn("active"),
		table.IntegerColumn("standalone"),
		table.TextColumn("primary_interface_bsd_name"),
		table.TextColumn("primary_interface_ip_address"),
		table.IntegerColumn("primary_interface_mbps"),
		table.TextColumn("primary_interface_user_readable"),
		table.IntegerColumn("primary_interface_wired"),
	}
}

func TetheratorStatusGenerate(ctx context.Context, queryContext table.QueryContext) ([]map[string]string, error) {
	var results []map[string]string

	status, err := GetTetheratorStatus()
	if err != nil {
		fmt.Println(err)
		return results, err
	}

	primaryInterface := status.Result.PrimaryInterface

	results = append(results, map[string]string{
		"active":                          fmt.Sprintf("%d", BoolToInt(status.Result.Active)),
		"standalone":                      fmt.Sprintf("%d", BoolToInt(status.Result.Standalone)),
		"primary_interface_bsd_name":      primaryInterface.BSDName,
		"primary_interface_ip_address":    primaryInterface.IPAddress,
		"primary_interface_mbps":          fmt.Sprintf("%d", primaryInterface.Mbps),
		"primary_interface_user_readable": primaryInterface.UserReadable,
		"primary_interface_wired":         fmt.Sprintf("%d", BoolToInt(primaryInterface.Wired)),
	})

	return results, nil
}
