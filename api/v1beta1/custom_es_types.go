package v1beta1

import (
	elasticsearch_types "github.com/elastic/go-elasticsearch/v8/typedapi/types"
	elasticsearch_types_indexprivilege "github.com/elastic/go-elasticsearch/v8/typedapi/types/enums/indexprivilege"
)

type CustomCustomManageUserPrivileges struct {
	Applications []string `json:"applications"`
}

func (r CustomCustomManageUserPrivileges) ToElasticsearchType() elasticsearch_types.ManageUserPrivileges {
	return elasticsearch_types.ManageUserPrivileges{
		Applications: r.Applications,
	}
}

type CustomApplicationGlobalUserPrivileges struct {
	Manage CustomCustomManageUserPrivileges `json:"manage"`
}

func (r CustomApplicationGlobalUserPrivileges) ToElasticsearchType() elasticsearch_types.ApplicationGlobalUserPrivileges {
	return elasticsearch_types.ApplicationGlobalUserPrivileges{
		Manage: r.Manage.ToElasticsearchType(),
	}
}

type CustomGlobalPrivilege struct {
	Application CustomApplicationGlobalUserPrivileges `json:"application"`
}

func (r CustomGlobalPrivilege) ToElasticsearchType() elasticsearch_types.GlobalPrivilege {
	return elasticsearch_types.GlobalPrivilege{
		Application: r.Application.ToElasticsearchType(),
	}
}

type CustomFieldSecurity struct {
	Except []string `json:"except,omitempty"`
	Grant  []string `json:"grant,omitempty"`
}

// https://github.com/elastic/go-elasticsearch/blob/main/typedapi/types/roledescriptor.go#L33

type CustomTransientMetadataConfig struct {
	Enabled bool `json:"enabled"`
}

type CustomApplicationPrivileges struct {
	// Application The name of the application to which this entry applies.
	Application string `json:"application"`
	// Privileges A list of strings, where each element is the name of an application privilege
	// or action.
	Privileges []string `json:"privileges"`
	// Resources A list resources to which the privileges are applied.
	Resources []string `json:"resources"`
}

func (r CustomApplicationPrivileges) ToElasticsearchType() elasticsearch_types.ApplicationPrivileges {
	return elasticsearch_types.ApplicationPrivileges{
		Application: r.Application,
		Resources:   r.Resources,
		Privileges:  r.Privileges,
	}
}

type CustomIndexPrivilege struct {
	Name string `json:"name"`
}

func (r CustomIndexPrivilege) ToElasticsearchType() elasticsearch_types_indexprivilege.IndexPrivilege {
	return elasticsearch_types_indexprivilege.IndexPrivilege{
		Name: r.Name,
	}
}

type CustomIndicesPrivileges struct {
	AllowRestrictedIndices *bool                  `json:"allow_restricted_indices,omitempty"`
	FieldSecurity          *CustomFieldSecurity   `json:"field_security,omitempty"`
	Names                  []string               `json:"names"`
	Privileges             []CustomIndexPrivilege `json:"privileges"`

	// This should support any of these, but we don't
	//
	//	string
	//	Query
	//	RoleTemplateQuery
	//
	Query string `json:"query,omitempty"`
}

func (r CustomIndicesPrivileges) ToElasticsearchType() elasticsearch_types.IndicesPrivileges {
	privileges := make([]elasticsearch_types_indexprivilege.IndexPrivilege, len(r.Privileges))

	for i, customType := range r.Privileges {
		privileges[i] = customType.ToElasticsearchType()
	}

	ret := elasticsearch_types.IndicesPrivileges{
		AllowRestrictedIndices: r.AllowRestrictedIndices,
		Names:                  r.Names,
		Privileges:             privileges,
		Query:                  r.Query,
	}

	if r.FieldSecurity != nil {
		ret.FieldSecurity = &elasticsearch_types.FieldSecurity{
			Except: r.FieldSecurity.Except,
			Grant:  r.FieldSecurity.Grant,
		}
	}

	return ret
}

type CustomRoleDescriptor struct {
	// there's a missing json tag in _one_ field from the Elasticsearch SDK, so here we are.

	// Applications A list of application privilege entries
	Applications []CustomApplicationPrivileges `json:"applications,omitempty"`
	// Cluster A list of cluster privileges. These privileges define the cluster level
	// actions that API keys are able to execute.
	Cluster []string `json:"cluster,omitempty"`
	// Global An object defining global privileges. A global privilege is a form of cluster
	// privilege that is request-aware. Support for global privileges is currently
	// limited to the management of application privileges.
	Global []CustomGlobalPrivilege `json:"global,omitempty"`
	// Indices A list of indices permissions entries.
	Indices []CustomIndicesPrivileges `json:"indices,omitempty"`
	// Metadata Optional meta-data. Within the metadata object, keys that begin with `_` are
	// reserved for system usage.
	Metadata elasticsearch_types.Metadata `json:"metadata,omitempty"`
	// RunAs A list of users that the API keys can impersonate.
	RunAs             []string                       `json:"run_as,omitempty"`
	TransientMetadata *CustomTransientMetadataConfig `json:"transient_metadata,omitempty"`
}

func (rd CustomRoleDescriptor) ToElasticsearchType() elasticsearch_types.RoleDescriptor {
	applications := make([]elasticsearch_types.ApplicationPrivileges, len(rd.Applications))

	for i, customType := range rd.Applications {
		applications[i] = customType.ToElasticsearchType()
	}

	indices := make([]elasticsearch_types.IndicesPrivileges, len(rd.Indices))

	for i, customType := range rd.Indices {
		indices[i] = customType.ToElasticsearchType()
	}

	global := make([]elasticsearch_types.GlobalPrivilege, len(rd.Global))

	for i, customType := range rd.Global {
		global[i] = customType.ToElasticsearchType()
	}

	ret := elasticsearch_types.RoleDescriptor{
		Applications: applications,
		Cluster:      rd.Cluster,
		Global:       global,
		Indices:      indices,
		Metadata:     rd.Metadata,
		RunAs:        rd.RunAs,
	}

	if rd.TransientMetadata != nil {
		ret.TransientMetadata = &elasticsearch_types.TransientMetadataConfig{
			Enabled: rd.TransientMetadata.Enabled,
		}
	}

	return ret
}
