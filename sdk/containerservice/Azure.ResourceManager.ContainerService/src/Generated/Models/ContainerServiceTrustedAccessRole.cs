// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

// <auto-generated/>

#nullable disable

using System.Collections.Generic;
using Azure.Core;

namespace Azure.ResourceManager.ContainerService.Models
{
    /// <summary> Trusted access role definition. </summary>
    public partial class ContainerServiceTrustedAccessRole
    {
        /// <summary> Initializes a new instance of <see cref="ContainerServiceTrustedAccessRole"/>. </summary>
        internal ContainerServiceTrustedAccessRole()
        {
            Rules = new ChangeTrackingList<ContainerServiceTrustedAccessRoleRule>();
        }

        /// <summary> Initializes a new instance of <see cref="ContainerServiceTrustedAccessRole"/>. </summary>
        /// <param name="sourceResourceType"> Resource type of Azure resource. </param>
        /// <param name="name"> Name of role, name is unique under a source resource type. </param>
        /// <param name="rules"> List of rules for the role. This maps to 'rules' property of [Kubernetes Cluster Role](https://kubernetes.io/docs/reference/kubernetes-api/authorization-resources/cluster-role-v1/#ClusterRole). </param>
        internal ContainerServiceTrustedAccessRole(string sourceResourceType, string name, IReadOnlyList<ContainerServiceTrustedAccessRoleRule> rules)
        {
            SourceResourceType = sourceResourceType;
            Name = name;
            Rules = rules;
        }

        /// <summary> Resource type of Azure resource. </summary>
        public string SourceResourceType { get; }
        /// <summary> Name of role, name is unique under a source resource type. </summary>
        public string Name { get; }
        /// <summary> List of rules for the role. This maps to 'rules' property of [Kubernetes Cluster Role](https://kubernetes.io/docs/reference/kubernetes-api/authorization-resources/cluster-role-v1/#ClusterRole). </summary>
        public IReadOnlyList<ContainerServiceTrustedAccessRoleRule> Rules { get; }
    }
}
