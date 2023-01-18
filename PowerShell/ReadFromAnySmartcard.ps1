<#
I stumbled across this function when I was searching for a way to make use of a credential with high privileges that were stored on a smartcard and had all logins denied on the local machine.
As it wa not a fully fletched smartcard EKU certificate, I could not use it for RDP logons on remote machines.
So this function allowed me to create a PSCredential which can then be used to run some powershell functions remotely :)
If you do have local admin rights on a machine and there is an interestig cert, you could try create a virtual smartcard (privided you have a TPM), export it from the local store and importit into the
virtual smartcard.
Then you can make use of the function to create a PSCredential from it for possible remote access
#>


Function Get-SmartCardCred{
<#
.SYNOPSIS
Get certificate credentials from the user's certificate store.

.DESCRIPTION
Returns a PSCredential object of the user's selected certificate.

.EXAMPLE
Get-SmartCardCred
UserName                                           Password
--------                                           --------
@@BVkEYkWiqJgd2d9xz3-5BiHs1cAN System.Security.SecureString

.EXAMPLE
$Cred = Get-SmartCardCred

.OUTPUTS
[System.Management.Automation.PSCredential]

.NOTES
Author: Joshua Chase
Last Modified: 13 January 2023 by Daniel Sangaree (dsangaree) and Elliot Fox (elfox-io)
-Removed X509Certificate2 usage in C# to make compatible with Powershell 7/.NET Core
-Added filtering to remove expired certs and filter by cert FriendlyName
Last Modified: 21 Juni 2021 by Sebastian Bammer-Tasch
Changed a few lines so the code works without UI directly from a (reverse) shell
Last Modified: 01 August 2018
C# code used from https://github.com/bongiovimatthew-microsoft/pscredentialWithCert

#>
[cmdletbinding()]
param(
    [Parameter(HelpMessage="Show All Available Certs")]
    [switch]$All = $False
)

    # Filters out expired certs by default; can optionally filter by string, as well
    $CertFilterString = "*"

    $SmartCardCode = @"
// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System;
using System.Management.Automation;
using System.Runtime.InteropServices;
using System.Security;
using System.Security.Cryptography.X509Certificates;


namespace SmartCardLogon{

    static class NativeMethods
    {

        public enum CRED_MARSHAL_TYPE
        {
            CertCredential = 1,
            UsernameTargetCredential
        }

        [StructLayout(LayoutKind.Sequential)]
        internal struct CERT_CREDENTIAL_INFO
        {
            public uint cbSize;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 20)]
            public byte[] rgbHashOfCert;
        }

        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        public static extern bool CredMarshalCredential(
            CRED_MARSHAL_TYPE CredType,
            IntPtr Credential,
            out IntPtr MarshaledCredential
        );

        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern bool CredFree([In] IntPtr buffer);

    }

    public class Certificate
    {

        public static PSCredential MarshalFlow(string thumbprint, SecureString pin)
        {
            //
            // Set up the data struct
            //
            NativeMethods.CERT_CREDENTIAL_INFO certInfo = new NativeMethods.CERT_CREDENTIAL_INFO();
            certInfo.cbSize = (uint)Marshal.SizeOf(typeof(NativeMethods.CERT_CREDENTIAL_INFO));

            //
            // Locate the certificate in the certificate store 
            //
            X509Store userMyStore = new X509Store(StoreName.My, StoreLocation.CurrentUser);
            userMyStore.Open(OpenFlags.ReadOnly);
            X509Certificate2Collection certsReturned = userMyStore.Certificates.Find(X509FindType.FindByThumbprint, thumbprint, false);
            userMyStore.Close();

            if (certsReturned.Count == 0)
            {
                throw new Exception("Unable to find the specified certificate.");
            }

            //
            // Marshal the certificate 
            //
            certInfo.rgbHashOfCert = certsReturned[0].GetCertHash();
            int size = Marshal.SizeOf(certInfo);
            IntPtr pCertInfo = Marshal.AllocHGlobal(size);
            Marshal.StructureToPtr(certInfo, pCertInfo, false);
            IntPtr marshaledCredential = IntPtr.Zero;
            bool result = NativeMethods.CredMarshalCredential(NativeMethods.CRED_MARSHAL_TYPE.CertCredential, pCertInfo, out marshaledCredential);

            string certBlobForUsername = null;
            PSCredential psCreds = null;

            if (result)
            {
                certBlobForUsername = Marshal.PtrToStringUni(marshaledCredential);
                psCreds = new PSCredential(certBlobForUsername, pin);
            }
            
            Marshal.FreeHGlobal(pCertInfo);
            if (marshaledCredential != IntPtr.Zero)
            {
                NativeMethods.CredFree(marshaledCredential);
            }
            
            return psCreds;
        }
    }
}
"@

    Add-Type -TypeDefinition $SmartCardCode -Language CSharp
    Add-Type -AssemblyName System.Security
    $FilteredCerts = @()
    if(! $All) {
        # Ignore expired certs and filter by FriendlyName
        $ValidCerts = [System.Security.Cryptography.X509Certificates.X509Certificate2[]](Get-ChildItem 'Cert:\CurrentUser\My' | Where-Object {$_.NotAfter -gt (get-date)})
        for ($i=0;$i -lt $ValidCerts.Count;$i++) {
            if ($ValidCerts[$i].FriendlyName -ilike $CertFilterString) {
                $FilteredCerts += $ValidCerts[$i] }
        }
    }
    else {
        # Return all certs, regardless of expiration date or FriendlyName, called by -All parameter
        $FilteredCerts = [System.Security.Cryptography.X509Certificates.X509Certificate2[]](Get-ChildItem 'Cert:\CurrentUser\My')
    }
    Write-Host "### Choose From Certs ###`n"
    for ($i=0;$i -lt $FilteredCerts.Count;$i++) {
        write-host "$i`t$(($FilteredCerts[$i].FriendlyName))`t($($FilteredCerts[$i].SubjectName.Name))" 
    }
    $CertIndex = read-host -prompt "Select certificate number"
    $cert = $FilteredCerts[$CertIndex]

    $Pin = Read-Host "Enter your PIN: " -AsSecureString

    Write-Output ([SmartCardLogon.Certificate]::MarshalFlow($Cert.Thumbprint, $Pin))
}


# $c = Get-SmartCardCred
# $s = new-PSSession -ComputerName <targetMachine> -Credential $c
# Enter-PSSession $s
# Copy-Item -Path <LocalPath> -Destination <LocalPathAtRemoteComputer> -ToSession $s
