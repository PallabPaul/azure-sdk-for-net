// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

// <auto-generated/>

#nullable disable

namespace Azure.ResourceManager.AppService.Models
{
    /// <summary> Site seal request. </summary>
    public partial class SiteSealContent
    {
        /// <summary> Initializes a new instance of <see cref="SiteSealContent"/>. </summary>
        public SiteSealContent()
        {
        }

        /// <summary> Initializes a new instance of <see cref="SiteSealContent"/>. </summary>
        /// <param name="isLightTheme"> If &lt;code&gt;true&lt;/code&gt; use the light color theme for site seal; otherwise, use the default color theme. </param>
        /// <param name="locale"> Locale of site seal. </param>
        internal SiteSealContent(bool? isLightTheme, string locale)
        {
            IsLightTheme = isLightTheme;
            Locale = locale;
        }

        /// <summary> If &lt;code&gt;true&lt;/code&gt; use the light color theme for site seal; otherwise, use the default color theme. </summary>
        public bool? IsLightTheme { get; set; }
        /// <summary> Locale of site seal. </summary>
        public string Locale { get; set; }
    }
}
