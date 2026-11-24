package arsenal

import "sort"

type Capability struct {
	Name, Category, Description, Availability string
	LabOnly, ExactApproval, MissionContext    bool
}

// Catalog describes executable capabilities and their gates, not simulated
// implementations of the paper's research modules.
func (registry *Registry) Catalog() []Capability {
	var capabilities []Capability
	for _, tool := range registry.All() {
		status := "available"
		if tool.Available != nil {
			if err := tool.Available(); err != nil {
				status = err.Error()
			}
		}
		capabilities = append(capabilities, Capability{Name: tool.Name, Category: tool.Category, Description: tool.Description, Availability: status, LabOnly: tool.LabOnly, ExactApproval: tool.LabOnly, MissionContext: tool.Internal})
	}
	sort.Slice(capabilities, func(i, j int) bool { return capabilities[i].Name < capabilities[j].Name })
	return capabilities
}
