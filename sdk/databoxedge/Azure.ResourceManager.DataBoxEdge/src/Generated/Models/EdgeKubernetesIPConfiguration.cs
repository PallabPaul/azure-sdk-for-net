// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

// <auto-generated/>

#nullable disable

namespace Azure.ResourceManager.DataBoxEdge.Models
{
    /// <summary> Kubernetes node IP configuration. </summary>
    public partial class EdgeKubernetesIPConfiguration
    {
        /// <summary> Initializes a new instance of <see cref="EdgeKubernetesIPConfiguration"/>. </summary>
        internal EdgeKubernetesIPConfiguration()
        {
        }

        /// <summary> Initializes a new instance of <see cref="EdgeKubernetesIPConfiguration"/>. </summary>
        /// <param name="port"> Port of the Kubernetes node. </param>
        /// <param name="ipAddress"> IP address of the Kubernetes node. </param>
        internal EdgeKubernetesIPConfiguration(string port, string ipAddress)
        {
            Port = port;
            IPAddress = ipAddress;
        }

        /// <summary> Port of the Kubernetes node. </summary>
        public string Port { get; }
        /// <summary> IP address of the Kubernetes node. </summary>
        public string IPAddress { get; }
    }
}
