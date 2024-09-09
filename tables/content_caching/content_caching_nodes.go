package content_caching

import (
	"context"
	"fmt"

	"github.com/macadmins/osquery-extension/pkg/utils"
	"github.com/osquery/osquery-go/plugin/table"
)

func CCNodesColumns() []table.ColumnDefinition {
	return []table.ColumnDefinition{
		table.TextColumn("type"),
		table.TextColumn("address"),
		table.IntegerColumn("ac_power"),
		table.BigIntColumn("cache_size"),
		table.IntegerColumn("im"),
		table.IntegerColumn("ns"),
		table.IntegerColumn("pc"),
		table.IntegerColumn("query_parameters"),
		table.IntegerColumn("sc"),
		table.IntegerColumn("ur"),
		table.IntegerColumn("is_portable"),
		table.IntegerColumn("local_network_speed"),
		table.IntegerColumn("local_network_wired"),
		table.IntegerColumn("friendly"),
		table.TextColumn("guid"),
		table.IntegerColumn("healthy"),
		table.IntegerColumn("port"),
		table.TextColumn("version"),
	}
}

func marshalCCNodes(nodes []Node, isParent bool) []map[string]string {
	var results []map[string]string
	for _, node := range nodes {
		nodeData := map[string]string{
			"address":          node.Address,
			"ac_power":         BoolToString(node.Details.AcPower),
			"cache_size":       IntToString(node.Details.CacheSize),
			"im":               BoolToString(node.Details.Capabilities.Im),
			"ns":               BoolToString(node.Details.Capabilities.Ns),
			"pc":               BoolToString(node.Details.Capabilities.Pc),
			"query_parameters": BoolToString(node.Details.Capabilities.QueryParameters),
			"sc":               BoolToString(node.Details.Capabilities.Sc),
			"ur":               BoolToString(node.Details.Capabilities.Ur),
			"is_portable":      BoolToString(node.Details.IsPortable),
			"guid":             node.GUID,
			"healthy":          BoolToString(node.Healthy),
			"port":             IntToString(node.Port),
			"version":          node.Version,
		}

		// Append only first local network for now
		if len(node.Details.LocalNetwork) > 0 {
			firstLocalNetwork := node.Details.LocalNetwork[0]
			nodeData["local_network_speed"] = IntToString(firstLocalNetwork.Speed)
			nodeData["local_network_wired"] = BoolToString(firstLocalNetwork.Wired)
		}

		if isParent {
			nodeData["type"] = "parent"
		} else {
			nodeData["type"] = "peer"
		}

		// Friendly field is not present in the parent json. Check for nil regardless of type
		if node.Friendly != nil {
			nodeData["friendly"] = BoolToString(*node.Friendly)
		} else {
			nodeData["friendly"] = ""
		}

		results = append(results, nodeData)
	}

	return results
}

func marshalAllCCNodes(commandOutput CommandOutput) []map[string]string {
	var results []map[string]string

	peers := marshalCCNodes(commandOutput.Result.Peers, false)
	results = append(results, peers...)

	parents := marshalCCNodes(commandOutput.Result.Parents, true)
	results = append(results, parents...)

	return results
}

func CCNodesGenerate(ctx context.Context, queryContext table.QueryContext) ([]map[string]string, error) {
	var results []map[string]string
	cmdExecutor := utils.NewRunner()
	status, err := getCommandOutput(cmdExecutor)
	if err != nil {
		fmt.Println(err)
		return results, err
	}

	results = marshalAllCCNodes(status)

	return results, nil
}
