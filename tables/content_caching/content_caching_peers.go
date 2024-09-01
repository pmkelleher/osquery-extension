package content_caching

import (
	"context"
	"fmt"

	"github.com/osquery/osquery-go/plugin/table"
)

func CCPeersColumns() []table.ColumnDefinition {
	return []table.ColumnDefinition{
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

func marshalCCPeers(commandOutput CommandOutput) []map[string]string {
	var results []map[string]string

	for _, peer := range commandOutput.Result.Peers {
		peerData := map[string]string{
			"address":          peer.Address,
			"ac_power":         BoolToString(peer.Details.AcPower),
			"cache_size":       IntToString(peer.Details.CacheSize),
			"im":               BoolToString(peer.Details.Capabilities.Im),
			"ns":               BoolToString(peer.Details.Capabilities.Ns),
			"pc":               BoolToString(peer.Details.Capabilities.Pc),
			"query_parameters": BoolToString(peer.Details.Capabilities.QueryParameters),
			"sc":               BoolToString(peer.Details.Capabilities.Sc),
			"ur":               BoolToString(peer.Details.Capabilities.Ur),
			"is_portable":      BoolToString(peer.Details.IsPortable),
			"friendly":         BoolToString(peer.Friendly),
			"guid":             peer.GUID,
			"healthy":          BoolToString(peer.Healthy),
			"port":             IntToString(peer.Port),
			"version":          peer.Version,
		}

		// Append only first local network for now
		if len(peer.Details.LocalNetwork) > 0 {
			firstLocalNetwork := peer.Details.LocalNetwork[0]
			peerData["local_network_speed"] = IntToString(firstLocalNetwork.Speed)
			peerData["local_network_wired"] = BoolToString(firstLocalNetwork.Wired)
		}
		results = append(results, peerData)
	}

	return results
}

func CCPeersGenerate(ctx context.Context, queryContext table.QueryContext) ([]map[string]string, error) {
	var results []map[string]string
	cmdExecutor := CmdExecutor{}
	status, err := getCommandOutput(cmdExecutor)
	if err != nil {
		fmt.Println(err)
		return results, err
	}

	results = marshalCCPeers(status)

	return results, nil
}
