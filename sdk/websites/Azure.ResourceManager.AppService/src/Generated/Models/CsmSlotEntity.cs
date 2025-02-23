// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

// <auto-generated/>

#nullable disable

using System;
using Azure.Core;

namespace Azure.ResourceManager.AppService.Models
{
    /// <summary> Deployment slot parameters. </summary>
    public partial class CsmSlotEntity
    {
        /// <summary> Initializes a new instance of <see cref="CsmSlotEntity"/>. </summary>
        /// <param name="targetSlot"> Destination deployment slot during swap operation. </param>
        /// <param name="preserveVnet"> &lt;code&gt;true&lt;/code&gt; to preserve Virtual Network to the slot during swap; otherwise, &lt;code&gt;false&lt;/code&gt;. </param>
        /// <exception cref="ArgumentNullException"> <paramref name="targetSlot"/> is null. </exception>
        public CsmSlotEntity(string targetSlot, bool preserveVnet)
        {
            Argument.AssertNotNull(targetSlot, nameof(targetSlot));

            TargetSlot = targetSlot;
            PreserveVnet = preserveVnet;
        }

        /// <summary> Destination deployment slot during swap operation. </summary>
        public string TargetSlot { get; }
        /// <summary> &lt;code&gt;true&lt;/code&gt; to preserve Virtual Network to the slot during swap; otherwise, &lt;code&gt;false&lt;/code&gt;. </summary>
        public bool PreserveVnet { get; }
    }
}
