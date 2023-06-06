// Copyright (c) Barry Dorrans. All rights reserved.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.
using System;

namespace idunno.Authentication.Basic
{
    /// <summary>
    /// Defines the encoding to be used for decoding user names and passwords.
    /// </summary>
    public enum EncodingPreference
    {
        /// <summary>
        /// Indicates that Unicode should be the only encoding tried when decoding user names and passwords.
        /// </summary>
        Unicode = 0,

        /// <summary>
        /// Indicates that ISO-8859-1/Latin1 should be the only encoding tried when decoding user names and passwords.
        /// </summary>
        Latin1 = 1,

        /// <summary>
        /// Indicates that Unicode should be tried first when decoding user names and passwords,
        /// and if an exception is thrown ISO-8859-1/Latin1 decoding will then be tried.
        ///
        /// Any Unicode exceptions will be swallowed, only exceptions from ISO-8859-1/Latin1 decoding will be thrown.
        /// </summary>
        PreferUnicode = 2,

        /// <summary>
        /// Indicates that ISO-8859-1/Latin1 should be tried first when decoding user names and passwords,
        /// and if an exception is thrown Unicode decoding will then be tried.
        ///
        /// Any ISO-8859-1 exceptions will be swallowed, only exceptions from Unicode decoding will be thrown.
        PreferLatin1 = 3
    }
}
