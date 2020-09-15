<#PSScriptInfo
.VERSION 1.0.1
.GUID 325f7f9a-87be-42ec-ba96-c5e423718284
.AUTHOR TRAB
.COMPANYNAME
.COPYRIGHT
.TAGS KeyTab Ktpass Key Tab
.LICENSEURI https://github.com/TheRealAdamBurford/Create-KeyTab/blob/master/LICENSE
.PROJECTURI https://github.com/TheRealAdamBurford/Create-KeyTab
.ICONURI
.EXTERNALMODULEDEPENDENCIES 
.REQUIREDSCRIPTS
.EXTERNALSCRIPTDEPENDENCIES
.RELEASENOTES
.PRIVATEDATA
#>

<# 
.DESCRIPTION 
 This scipt will generate off-line keytab files for use with Active Directory (AD). While the script is designed to work independently of AD, this script can be used with a wrapper script that uses Get-ADUser or Get-ADObject to retrieve the UPN of a samaccountname or a list of samaccountnames for use in batch processing of KeyTab creation. More information at https://therealadamburford.github.io/Create-KeyTab/ 
#> 
##########################################################
###
###      Create-KeyTab.ps1
###
###      Created : 2019-10-26
###      Modified: 2020-09-15
###
###      Created By : Adam Burford
###      Modified By: Adam Burford
###
###
### Notes: Create RC4-HMAC, AES128. AES256 KeyTab file. Does not use AD. 
### Password, ServicePRincipal/UPN must be set on AD account.
### Future add may include option AD lookup for Kvno, SPN and UPN.
###
### 2019-11-11 - Added custom SALT option
### 2019-11-11 - Added current Epoch Time Stamp.
### 2019-11-12 - Added -Append option
### 2019-11-12 - Added -Quiet and -NoPrompt switches for use in batch mode
### 2019-11-14 - Added support for UPN format primary/principal (e.g. host/www.domain.com). The principal is split into an array. 
###              The slash is removed from the SALT calculation.
###
### 2019-11-18 - Changed output text. RC4,AES128,AES256
### 2019-11-18 - Created static nFold output.
### 2019-11-26 - Added a Get-Password function to mask password prompt input
### 2020-01-30 - Add Info for posting to https://www.powershellgallery.com
### 2020-09-15 - Added suggested use of [decimal]::Parse from "https://github.com/matherm-aboehm" to fix timestamp error on localized versions of Windows. Line 535.
###
##########################################################
### Attribution:
### https://tools.ietf.org/html/rfc3961
### https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-kile/936a4878-9462-4753-aac8-087cd3ca4625?redirectedfrom=MSDN
### https://github.com/dfinke/powershell-algorithms/blob/master/src/algorithms/math/euclidean-algorithm/euclideanAlgorithm.ps1
### https://afana.me/archive/2016/12/29/how-mit-keytab-files-store-passwords.aspx/
### http://www.ioplex.com/utilities/keytab.txt

<#
.SYNOPSIS
This script will generate and append version 502 KeyTab files

.DESCRIPTION
Required Parameters

-Realm     : The Realm for the KeyTab
-Principal : The Principal for the KeyTab. Case sensative for AES SALT. Default REALM+Principal
-Password  : 

Optional Parameters

-SALT      : Use a custom SALT
-File      : KeyTab File Path. Default = CurrentDirectory\login.keytab
-KVNO      : Default = 1. Exceeding 255 will wrap the KVNO. THe 32bit KVNO field is not implimented.
-PType     : Default = KRB5_NT_PRINCIPAL
-RC4       : Generate RC4 Key
-AES128    : Generate AES128 Key
-AES256    : Generate AES256 Key - This is default if no Etype switch is set.
-Append    : Append Key Data to an existing KeyTab file.
-Quiet     : Suppress Text Output
-NoPrompt  : Suppress Write KeyTab File Prompt

.EXAMPLE
.\Create-KeyTab.ps1
.EXAMPLE
.\Create-KeyTab.ps1 -AES256 -AES128 -RC4
.EXAMPLE
.\Create-KeyTab.ps1 -AES256 -AES128 -Append
.EXAMPLE
.\Create-KeyTab.ps1 -AES256 -AES128 -SALT "MY.REALM.COMprincipalname"
.EXAMPLE
.\Create-KeyTab.ps1 -Realm "MY.REALM.COM" -Principal "principalname" -Password "Secret" -File "c:\temp\login.keytab"

.NOTES
Use -QUIET and -NOPROMPT for batch mode processing.

.LINK
https://www.linkedin.com/in/adamburford
#>
param (
[Parameter(Mandatory=$true,HelpMessage="REALM name will be forced to Upper Case")]$Realm,
[Parameter(Mandatory=$true,HelpMessage="Principal is case sensative. It must match the principal portion of the UPN",ValueFromPipelineByPropertyName=$true)]$Principal,
[Parameter(Mandatory=$false)]$Password,
[Parameter(Mandatory=$false)]$SALT,
[Parameter(Mandatory=$false)]$File,
[Parameter(Mandatory=$false,ValueFromPipelineByPropertyName=$true)]$KVNO=1,
[Parameter(Mandatory=$false)][ValidateSet("KRB5_NT_PRINCIPAL", "KRB5_NT_SRV_INST", "KRB5_NT_UID")][String[]]$PType="KRB5_NT_PRINCIPAL",
[Parameter(Mandatory=$false)][Switch]$RC4,
[Parameter(Mandatory=$false)][Switch]$AES128,
[Parameter(Mandatory=$false)][Switch]$AES256,
[Parameter(Mandatory=$false)][Switch]$Append,
[Parameter(Mandatory=$false)][Switch]$Quiet,
[Parameter(Mandatory=$false)][Switch]$NoPrompt
)

function Get-MD4{
    PARAM(
        [String]$String,
        [Byte[]]$bArray,
        [Switch]$UpperCase
    )
    
    # Author: Larry.Song@outlook.com
    # https://github.com/LarrysGIT/MD4-powershell
    # Reference: https://tools.ietf.org/html/rfc1320
    # MD4('abc'): a448017aaf21d8525fc10ae87aa6729d
    $Array = [byte[]]@()
    if($String)
    {
        $Array = [byte[]]@($String.ToCharArray() | %{[int]$_})
    }
    if($bArray)
    {
        $Array = $bArray
    }
    # padding 100000*** to length 448, last (64 bits / 8) 8 bytes fill with original length
    # at least one (512 bits / 8) 64 bytes array
    $M = New-Object Byte[] (([math]::Floor($Array.Count/64) + 1) * 64)
    # copy original byte array, start from index 0
    $Array.CopyTo($M, 0)
    # padding bits 1000 0000
    $M[$Array.Count] = 0x80
    # padding bits 0000 0000 to fill length (448 bits /8) 56 bytes
    # Default value is 0 when creating a new byte array, so, no action
    # padding message length to the last 64 bits
    @([BitConverter]::GetBytes($Array.Count * 8)).CopyTo($M, $M.Count - 8)

    # message digest buffer (A,B,C,D)
    $A = [Convert]::ToUInt32('0x67452301', 16)
    $B = [Convert]::ToUInt32('0xefcdab89', 16)
    $C = [Convert]::ToUInt32('0x98badcfe', 16)
    $D = [Convert]::ToUInt32('0x10325476', 16)
    
    # There is no unsigned number shift in C#, have to define one.
    Add-Type -TypeDefinition @'
public class Shift
{
  public static uint Left(uint a, int b)
    {
        return ((a << b) | (((a >> 1) & 0x7fffffff) >> (32 - b - 1)));
    }
}
'@

    # define 3 auxiliary functions
    function FF([uint32]$X, [uint32]$Y, [uint32]$Z)
    {
        (($X -band $Y) -bor ((-bnot $X) -band $Z))
    }
    function GG([uint32]$X, [uint32]$Y, [uint32]$Z)
    {
        (($X -band $Y) -bor ($X -band $Z) -bor ($Y -band $Z))
    }
    function HH([uint32]$X, [uint32]$Y, [uint32]$Z){
        ($X -bxor $Y -bxor $Z)
    }
    # processing message in one-word blocks
    for($i = 0; $i -lt $M.Count; $i += 64)
    {
        # Save a copy of A/B/C/D
        $AA = $A
        $BB = $B
        $CC = $C
        $DD = $D

        # Round 1 start
        $A = [Shift]::Left(($A + (FF -X $B -Y $C -Z $D) + [BitConverter]::ToUInt32($M[($i + 0)..($i + 3)], 0)) -band [uint32]::MaxValue, 3)
        $D = [Shift]::Left(($D + (FF -X $A -Y $B -Z $C) + [BitConverter]::ToUInt32($M[($i + 4)..($i + 7)], 0)) -band [uint32]::MaxValue, 7)
        $C = [Shift]::Left(($C + (FF -X $D -Y $A -Z $B) + [BitConverter]::ToUInt32($M[($i + 8)..($i + 11)], 0)) -band [uint32]::MaxValue, 11)
        $B = [Shift]::Left(($B + (FF -X $C -Y $D -Z $A) + [BitConverter]::ToUInt32($M[($i + 12)..($i + 15)], 0)) -band [uint32]::MaxValue, 19)

        $A = [Shift]::Left(($A + (FF -X $B -Y $C -Z $D) + [BitConverter]::ToUInt32($M[($i + 16)..($i + 19)], 0)) -band [uint32]::MaxValue, 3)
        $D = [Shift]::Left(($D + (FF -X $A -Y $B -Z $C) + [BitConverter]::ToUInt32($M[($i + 20)..($i + 23)], 0)) -band [uint32]::MaxValue, 7)
        $C = [Shift]::Left(($C + (FF -X $D -Y $A -Z $B) + [BitConverter]::ToUInt32($M[($i + 24)..($i + 27)], 0)) -band [uint32]::MaxValue, 11)
        $B = [Shift]::Left(($B + (FF -X $C -Y $D -Z $A) + [BitConverter]::ToUInt32($M[($i + 28)..($i + 31)], 0)) -band [uint32]::MaxValue, 19)

        $A = [Shift]::Left(($A + (FF -X $B -Y $C -Z $D) + [BitConverter]::ToUInt32($M[($i + 32)..($i + 35)], 0)) -band [uint32]::MaxValue, 3)
        $D = [Shift]::Left(($D + (FF -X $A -Y $B -Z $C) + [BitConverter]::ToUInt32($M[($i + 36)..($i + 39)], 0)) -band [uint32]::MaxValue, 7)
        $C = [Shift]::Left(($C + (FF -X $D -Y $A -Z $B) + [BitConverter]::ToUInt32($M[($i + 40)..($i + 43)], 0)) -band [uint32]::MaxValue, 11)
        $B = [Shift]::Left(($B + (FF -X $C -Y $D -Z $A) + [BitConverter]::ToUInt32($M[($i + 44)..($i + 47)], 0)) -band [uint32]::MaxValue, 19)

        $A = [Shift]::Left(($A + (FF -X $B -Y $C -Z $D) + [BitConverter]::ToUInt32($M[($i + 48)..($i + 51)], 0)) -band [uint32]::MaxValue, 3)
        $D = [Shift]::Left(($D + (FF -X $A -Y $B -Z $C) + [BitConverter]::ToUInt32($M[($i + 52)..($i + 55)], 0)) -band [uint32]::MaxValue, 7)
        $C = [Shift]::Left(($C + (FF -X $D -Y $A -Z $B) + [BitConverter]::ToUInt32($M[($i + 56)..($i + 59)], 0)) -band [uint32]::MaxValue, 11)
        $B = [Shift]::Left(($B + (FF -X $C -Y $D -Z $A) + [BitConverter]::ToUInt32($M[($i + 60)..($i + 63)], 0)) -band [uint32]::MaxValue, 19)
        # Round 1 end
        # Round 2 start
        $A = [Shift]::Left(($A + (GG -X $B -Y $C -Z $D) + [BitConverter]::ToUInt32($M[($i + 0)..($i + 3)], 0) + 0x5A827999) -band [uint32]::MaxValue, 3)
        $D = [Shift]::Left(($D + (GG -X $A -Y $B -Z $C) + [BitConverter]::ToUInt32($M[($i + 16)..($i + 19)], 0) + 0x5A827999) -band [uint32]::MaxValue, 5)
        $C = [Shift]::Left(($C + (GG -X $D -Y $A -Z $B) + [BitConverter]::ToUInt32($M[($i + 32)..($i + 35)], 0) + 0x5A827999) -band [uint32]::MaxValue, 9)
        $B = [Shift]::Left(($B + (GG -X $C -Y $D -Z $A) + [BitConverter]::ToUInt32($M[($i + 48)..($i + 51)], 0) + 0x5A827999) -band [uint32]::MaxValue, 13)

        $A = [Shift]::Left(($A + (GG -X $B -Y $C -Z $D) + [BitConverter]::ToUInt32($M[($i + 4)..($i + 7)], 0) + 0x5A827999) -band [uint32]::MaxValue, 3)
        $D = [Shift]::Left(($D + (GG -X $A -Y $B -Z $C) + [BitConverter]::ToUInt32($M[($i + 20)..($i + 23)], 0) + 0x5A827999) -band [uint32]::MaxValue, 5)
        $C = [Shift]::Left(($C + (GG -X $D -Y $A -Z $B) + [BitConverter]::ToUInt32($M[($i + 36)..($i + 39)], 0) + 0x5A827999) -band [uint32]::MaxValue, 9)
        $B = [Shift]::Left(($B + (GG -X $C -Y $D -Z $A) + [BitConverter]::ToUInt32($M[($i + 52)..($i + 55)], 0) + 0x5A827999) -band [uint32]::MaxValue, 13)

        $A = [Shift]::Left(($A + (GG -X $B -Y $C -Z $D) + [BitConverter]::ToUInt32($M[($i + 8)..($i + 11)], 0) + 0x5A827999) -band [uint32]::MaxValue, 3)
        $D = [Shift]::Left(($D + (GG -X $A -Y $B -Z $C) + [BitConverter]::ToUInt32($M[($i + 24)..($i + 27)], 0) + 0x5A827999) -band [uint32]::MaxValue, 5)
        $C = [Shift]::Left(($C + (GG -X $D -Y $A -Z $B) + [BitConverter]::ToUInt32($M[($i + 40)..($i + 43)], 0) + 0x5A827999) -band [uint32]::MaxValue, 9)
        $B = [Shift]::Left(($B + (GG -X $C -Y $D -Z $A) + [BitConverter]::ToUInt32($M[($i + 56)..($i + 59)], 0) + 0x5A827999) -band [uint32]::MaxValue, 13)

        $A = [Shift]::Left(($A + (GG -X $B -Y $C -Z $D) + [BitConverter]::ToUInt32($M[($i + 12)..($i + 15)], 0) + 0x5A827999) -band [uint32]::MaxValue, 3)
        $D = [Shift]::Left(($D + (GG -X $A -Y $B -Z $C) + [BitConverter]::ToUInt32($M[($i + 28)..($i + 31)], 0) + 0x5A827999) -band [uint32]::MaxValue, 5)
        $C = [Shift]::Left(($C + (GG -X $D -Y $A -Z $B) + [BitConverter]::ToUInt32($M[($i + 44)..($i + 47)], 0) + 0x5A827999) -band [uint32]::MaxValue, 9)
        $B = [Shift]::Left(($B + (GG -X $C -Y $D -Z $A) + [BitConverter]::ToUInt32($M[($i + 60)..($i + 63)], 0) + 0x5A827999) -band [uint32]::MaxValue, 13)
        # Round 2 end
        # Round 3 start
        $A = [Shift]::Left(($A + (HH -X $B -Y $C -Z $D) + [BitConverter]::ToUInt32($M[($i + 0)..($i + 3)], 0) + 0x6ED9EBA1) -band [uint32]::MaxValue, 3)
        $D = [Shift]::Left(($D + (HH -X $A -Y $B -Z $C) + [BitConverter]::ToUInt32($M[($i + 32)..($i + 35)], 0) + 0x6ED9EBA1) -band [uint32]::MaxValue, 9)
        $C = [Shift]::Left(($C + (HH -X $D -Y $A -Z $B) + [BitConverter]::ToUInt32($M[($i + 16)..($i + 19)], 0) + 0x6ED9EBA1) -band [uint32]::MaxValue, 11)
        $B = [Shift]::Left(($B + (HH -X $C -Y $D -Z $A) + [BitConverter]::ToUInt32($M[($i + 48)..($i + 51)], 0) + 0x6ED9EBA1) -band [uint32]::MaxValue, 15)

        $A = [Shift]::Left(($A + (HH -X $B -Y $C -Z $D) + [BitConverter]::ToUInt32($M[($i + 8)..($i + 11)], 0) + 0x6ED9EBA1) -band [uint32]::MaxValue, 3)
        $D = [Shift]::Left(($D + (HH -X $A -Y $B -Z $C) + [BitConverter]::ToUInt32($M[($i + 40)..($i + 43)], 0) + 0x6ED9EBA1) -band [uint32]::MaxValue, 9)
        $C = [Shift]::Left(($C + (HH -X $D -Y $A -Z $B) + [BitConverter]::ToUInt32($M[($i + 24)..($i + 27)], 0) + 0x6ED9EBA1) -band [uint32]::MaxValue, 11)
        $B = [Shift]::Left(($B + (HH -X $C -Y $D -Z $A) + [BitConverter]::ToUInt32($M[($i + 56)..($i + 59)], 0) + 0x6ED9EBA1) -band [uint32]::MaxValue, 15)

        $A = [Shift]::Left(($A + (HH -X $B -Y $C -Z $D) + [BitConverter]::ToUInt32($M[($i + 4)..($i + 7)], 0) + 0x6ED9EBA1) -band [uint32]::MaxValue, 3)
        $D = [Shift]::Left(($D + (HH -X $A -Y $B -Z $C) + [BitConverter]::ToUInt32($M[($i + 36)..($i + 39)], 0) + 0x6ED9EBA1) -band [uint32]::MaxValue, 9)
        $C = [Shift]::Left(($C + (HH -X $D -Y $A -Z $B) + [BitConverter]::ToUInt32($M[($i + 20)..($i + 23)], 0) + 0x6ED9EBA1) -band [uint32]::MaxValue, 11)
        $B = [Shift]::Left(($B + (HH -X $C -Y $D -Z $A) + [BitConverter]::ToUInt32($M[($i + 52)..($i + 55)], 0) + 0x6ED9EBA1) -band [uint32]::MaxValue, 15)

        $A = [Shift]::Left(($A + (HH -X $B -Y $C -Z $D) + [BitConverter]::ToUInt32($M[($i + 12)..($i + 15)], 0) + 0x6ED9EBA1) -band [uint32]::MaxValue, 3)
        $D = [Shift]::Left(($D + (HH -X $A -Y $B -Z $C) + [BitConverter]::ToUInt32($M[($i + 44)..($i + 47)], 0) + 0x6ED9EBA1) -band [uint32]::MaxValue, 9)
        $C = [Shift]::Left(($C + (HH -X $D -Y $A -Z $B) + [BitConverter]::ToUInt32($M[($i + 28)..($i + 31)], 0) + 0x6ED9EBA1) -band [uint32]::MaxValue, 11)
        $B = [Shift]::Left(($B + (HH -X $C -Y $D -Z $A) + [BitConverter]::ToUInt32($M[($i + 60)..($i + 63)], 0) + 0x6ED9EBA1) -band [uint32]::MaxValue, 15)
        # Round 3 end
        # Increment start
        $A = ($A + $AA) -band [uint32]::MaxValue
        $B = ($B + $BB) -band [uint32]::MaxValue
        $C = ($C + $CC) -band [uint32]::MaxValue
        $D = ($D + $DD) -band [uint32]::MaxValue
        # Increment end
    }
    # Output start
    $A = ('{0:x8}' -f $A) -ireplace '^(\w{2})(\w{2})(\w{2})(\w{2})$', '$4$3$2$1'
    $B = ('{0:x8}' -f $B) -ireplace '^(\w{2})(\w{2})(\w{2})(\w{2})$', '$4$3$2$1'
    $C = ('{0:x8}' -f $C) -ireplace '^(\w{2})(\w{2})(\w{2})(\w{2})$', '$4$3$2$1'
    $D = ('{0:x8}' -f $D) -ireplace '^(\w{2})(\w{2})(\w{2})(\w{2})$', '$4$3$2$1'
    # Output end

    if($UpperCase)
    {
        return "$A$B$C$D".ToUpper()
    }
    else
    {
        return "$A$B$C$D"
    }
}

function Get-PBKDF2 {
param (
[Parameter(Mandatory=$true)]$PasswordString,
[Parameter(Mandatory=$true)]$SALT,
[Parameter(Mandatory=$true)][ValidateSet("16", "32")][String[]]$KeySize
)

### Set Key Size
switch($KeySize){
"16"{
    [int] $size = 16
    break;
    }
"32"{
    [int] $size = 32
    break;
     }
default{}
}

[byte[]] $password = [Text.Encoding]::UTF8.GetBytes($PasswordString)
[byte[]] $saltBytes = [Text.Encoding]::UTF8.GetBytes($SALT)

#PBKDF2 IterationCount=4096
$deriveBytes = new-Object Security.Cryptography.Rfc2898DeriveBytes($password, $saltBytes, 4096)

<#
$hexStringSALT = Get-HexStringFromByteArray -Data $deriveBytes.Salt    
Write-Host "SALT (HEX):"$hexStringSALT -ForegroundColor Yellow
#>

return $deriveBytes.GetBytes($size)
}

function Encrypt-AES {
param (
[Parameter(Mandatory=$true)]$KeyData,
[Parameter(Mandatory=$true)]$IVData,
[Parameter(Mandatory=$true)]$Data
)

### AES 128-CTS
# KeySize = 16
# AESKey = Encrypt-AES -KeyData PBKdf2 -IVData IV -Data NFoldText

### AES 256-CTS
# KeySize = 32
# K1 = Encrypt-AES -KeyData PBKdf2 -IVData IV -Data NFoldText
# K2 = Encrypt-AES -KeyData PBKdf2 -IVData IV -Data K1
# AESKey = K1 + K2

# Create AES Object
    $Aes = $null
    $encryptor = $null
    $memStream = $null
    $cryptoStream = $null
    $AESKey = $null
    
    $Aes = New-Object System.Security.Cryptography.AesManaged
    $Aes.Mode = [System.Security.Cryptography.CipherMode]::CBC
    $Aes.Padding = [System.Security.Cryptography.PaddingMode]::None
    $Aes.BlockSize = 128

    $encryptor = $Aes.CreateEncryptor($key,$IV)
    $memStream = new-Object IO.MemoryStream

    [byte[]] $AESKey = @()
    $cryptoStream = New-Object System.Security.Cryptography.CryptoStream($memStream, $encryptor, [System.Security.Cryptography.CryptoStreamMode]::Write)
    $cryptoStream.Write($Data, 0, $Data.Length)
    $CryptoStream.FlushFinalBlock()
    $cryptoStream.Close()

    $AESKey = $memStream.ToArray()
    $memStream.Close()
    $Aes.Dispose()

    return $AESKey
}

function Get-AES128Key {
param (
[Parameter(Mandatory=$true)]$PasswordString,
[Parameter(Mandatory=$true)]$SALT=""
)

[byte[]] $PBKDF2 = Get-PBKDF2 -PasswordString $passwordString -SALT $SALT -KeySize 16
#[byte[]] $nFolded = (Get-NFold-Bytes -Data ([Text.Encoding]::ASCII.GetBytes("kerberos")) -KeySize 16)
[byte[]] $nFolded = @(107,101,114,98,101,114,111,115,123,155,91,43,147,19,43,147)
[byte[]] $Key = $PBKDF2
[byte[]] $IV =  @(0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0)

$AES128Key = Encrypt-AES -KeyData $key -IVData $IV -Data $nFolded
return $(Get-HexStringFromByteArray -Data $AES128Key)
}

function Get-AES256Key {
param (
[Parameter(Mandatory=$true)]$PasswordString,
[Parameter(Mandatory=$true)]$SALT=""
)

[byte[]] $PBKDF2 = Get-PBKDF2 -PasswordString $passwordString -SALT $SALT -KeySize 32
#[byte[]] $nFolded = (Get-NFold-Bytes -Data ([Text.Encoding]::ASCII.GetBytes("kerberos")) -KeySize 16)
[byte[]] $nFolded = @(107,101,114,98,101,114,111,115,123,155,91,43,147,19,43,147)
[byte[]] $Key = $PBKDF2
[byte[]] $IV =  @(0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0)

$k1 = Encrypt-AES -KeyData $key -IVData $IV -Data $nFolded
$k2 = Encrypt-AES -KeyData $key -IVData $IV -Data $k1

$AES256Key = $k1 + $k2
return $(Get-HexStringFromByteArray -Data $AES256Key)
}

function Get-HexStringFromByteArray{
param (
[Parameter(Mandatory=$true,Position=0)][byte[]]$Data
)
$hexString = $null

        $sb = New-Object System.Text.StringBuilder ($Data.Length * 2)
        foreach($b in $Data)
        {
            $sb.AppendFormat("{0:x2}", $b) |Out-Null
        }
        $hexString = $sb.ToString().ToUpper([CultureInfo]::InvariantCulture)

return $hexString
}

function Get-ByteArrayFromHexString{
param 
(
[Parameter(Mandatory=$true)][String]$HexString
)
        $i = 0;
        $bytes = @()
        while($i -lt $HexString.Length)
        {
            $chars = $HexString.SubString($i, 2)
            $b = [Convert]::ToByte($chars, 16)
            $bytes += $b
            $i = $i+2
        }
return $bytes
}

function Get-BytesBigEndian {
param (
[Parameter(Mandatory=$true)]$Value,
[Parameter(Mandatory=$true)][ValidateSet("16", "32")][String[]]$BitSize
)

### Set Key Type
[byte[]] $bytes = @()
switch($BitSize){
"16"{
    $bytes = [BitCOnverter]::GetBytes([int16]$Value)
    if([BitCOnverter]::IsLittleEndian){
    [Array]::Reverse($bytes)
    }
    break;
    }
"32"{
    $bytes = [BitCOnverter]::GetBytes([int32]$Value)
    if([BitCOnverter]::IsLittleEndian){
    [Array]::Reverse($bytes)
    }
    break;
     }
default{}
}

return $bytes
}

function Get-PrincipalType {
param (
[Parameter(Mandatory=$true)][ValidateSet("KRB5_NT_PRINCIPAL", "KRB5_NT_SRV_INST", "KRB5_NT_UID")][String[]]$PrincipalType
)

[byte[]] $nameType = @()

switch($PrincipalType){
"KRB5_NT_PRINCIPAL"{$nameType = @(00,00,00,01);break}
"KRB5_NT_SRV_INST"{$nameType = @(00,00,00,02);break}
"KRB5_NT_UID"{$nameType = @(00,00,00,05);break}
default{$nameType = @(00,00,00,01);break}
}

return $nameType
}

function Create-KeyTabEntry {
param (
[Parameter(Mandatory=$true)]$PasswordString,
[Parameter(Mandatory=$true)]$RealmString,
[Parameter(Mandatory=$true)]$Components,
[Parameter(Mandatory=$false)]$SALT="",
[Parameter(Mandatory=$false)]$KVNO=1,
[Parameter(Mandatory=$true)][ValidateSet("KRB5_NT_PRINCIPAL", "KRB5_NT_SRV_INST", "KRB5_NT_UID")][String[]]$PrincipalType,
[Parameter(Mandatory=$true)][ValidateSet("RC4", "AES128", "AES256")][String[]]$EncryptionKeyType
)

### Key Types: RC4 0x17 (23), AES128  0x11 (17), AES256  0x12 (18)

### Set Key Type
[byte[]] $keyType = @()
[byte[]] $sizeKeyBlock = @()

switch($EncryptionKeyType){
"RC4"{
       $keyType = @(00,23)
       $sizeKey = 16
       $sizeKeyBlock = @(00,16)
       ### Create RC4-HMAC Key. Unicode is required for MD4 hash input.
       [byte[]]$password = [Text.Encoding]::Unicode.GetBytes($passwordString)
       $keyBlock = Get-MD4 -bArray $password -UpperCase
       break
       }
"AES128"{
        $keyType = @(00,17)
        $sizeKey = 16
        $sizeKeyBlock = @(00,16)
        #$keyBlock = Get-AES128Key -PasswordString $passwordString -Realm $RealmString -Principal $PrincipalString -SALT $SALT
        $keyBlock = Get-AES128Key -PasswordString $passwordString -SALT $SALT
        break
        }
"AES256"{
        $keyType = @(00,18)
        $sizeKey = 32
        $sizeKeyBlock = @(00,32)
        #$keyBlock = Get-AES256Key -PasswordString $passwordString -Realm $RealmString -Principal $PrincipalString -SALT $SALT
        $keyBlock = Get-AES256Key -PasswordString $passwordString -SALT $SALT
        break
        }
default{}
}

### Set Principal Type
[byte[]] $nameType = @()
switch($PrincipalType){
"KRB5_NT_PRINCIPAL"{$nameType = @(00,00,00,01);break}
"KRB5_NT_SRV_INST"{$nameType = @(00,00,00,02);break}
"KRB5_NT_UID"{$nameType = @(00,00,00,05);break}
default{$nameType = @(00,00,00,01);break}
}

### KVNO larger than 255 requires 32bit KVNO field at the end of the record
$vno = @()

if($kvno -le 255){
$vno = @([byte]$kvno)
} else {
$vno = @(00)
}

[byte[]]$numComponents = Get-BytesBigEndian -BitSize 16 -Value $components.Count

### To Set TimeStamp To Jan 1, 1970 - [byte[]]$timeStamp = @(0,0,0,0)
### [byte[]]$timeStamp = Get-BytesBigEndian -BitSize 32 -Value ([int]([Math]::Truncate((Get-Date(Get-Date).ToUniversalTime() -UFormat %s))))
### 15 September 2020 Updated
### https://github.com/matherm-aboehm suggested use of [decimal]::Parse to fix timestamp error on localized versions of Windows.
[byte[]]$timeStamp = Get-BytesBigEndian -BitSize 32 -Value ([int]([Math]::Truncate([decimal]::Parse((Get-Date(Get-Date).ToUniversalTime() -UFormat %s)))))

### Data size information for KeyEntry
# num_components bytes   = 2
# realm bytes            = variable (2 bytes) + length
# components array bytes = varable (2 bytes) + length for each component. Component count should be typically 1 or 2.
# name type bytes        = 4
# timestamp bytes        = 4
# kvno bytes             = 1 or 4
# Key Type bytes         = 2
# Key bytes              = 2 + 16 or 32 "RC4 and AES128 are 16 Byte Keys. AES 256 is 32"

$sizeRealm  = Get-BytesBigEndian -Value ([Text.Encoding]::UTF8.GetByteCount($realmString)) -BitSize 16
[Int32]$sizeKeyTabEntry = 2 #NumComponentsSize
$sizeKeyTabEntry += 2 #RealmLength Byte Count 
$sizeKeyTabEntry += ([Text.Encoding]::UTF8.GetByteCount($realmString))
    foreach($principal in $Components){
    $sizePrincipal = ([Text.Encoding]::UTF8.GetByteCount($principal))
    $sizeKeyTabEntry += $sizePrincipal + 2
    }
$sizeKeyTabEntry += 4 #NameType
$sizeKeyTabEntry += 4 #TimeStamp
$sizeKeyTabEntry += 1 #KVNO 8bit
$sizeKeyTabEntry += 2 #KeyType
$sizeKeyTabEntry += 2 #Key Length Count
$sizeKeyTabEntry += $sizeKey

$sizeTotal = Get-BytesBigEndian -Value $sizeKeyTabEntry -BitSize 32

[byte[]] $keytabEntry = @()
$keytabEntry += $sizeTotal
$keytabEntry += $numComponents
$keytabEntry += $sizeRealm
$keytabEntry += [byte[]][Text.Encoding]::UTF8.GetBytes($realmString)
    foreach($principal in $Components){
    $sizePrincipal = Get-BytesBigEndian -Value ([Text.Encoding]::UTF8.GetByteCount($principal)) -BitSize 16
    $keytabEntry += $sizePrincipal
    $keytabEntry += [byte[]][Text.Encoding]::UTF8.GetBytes($principal)
    }
$keytabEntry += $nameType
$keytabEntry += $timeStamp
$keytabEntry += $vno
$keytabEntry += $keyType
$keytabEntry += $sizeKeyBlock
$keytabEntry += Get-ByteArrayFromHexString -HexString $keyBlock

$keytabEntryObject = [PsCustomObject]@{
        Size           = $sizeKeyTabEntry
        NumComponents  = $numComponents
        Realm          = [byte[]][Text.Encoding]::UTF8.GetBytes($realmString)
        Components     = $components
        NameType       = $nameType
        TimeStamp      = $timeStamp
        KeyType        = $keyType
        KeyBlock       = $keyBlock
        KeytabEntry    = $keytabEntry
    }
return $keytabEntryObject
}

Function Get-Password {

        $passwordSecure = Read-Host -Prompt "Enter Password" -AsSecureString
        $passwordBSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($passwordSecure)
        $password = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($passwordBSTR)


return $password
}


if ([string]::IsNullOrEmpty($Password)){$Password = $(Get-Password)}

if ([string]::IsNullOrEmpty($File)){$File=$(Get-Location).Path+'\login.keytab'}

if($Quiet) {
$Script:Silent = $true
} else {
$Script:Silent = $false
}

### Force Realm to UPPERCASE
$Realm = $Realm.ToUpper()

### The Components array splits the primary/principal.
$PrincipalArray = @()
$PrincipalArray = $Principal.Split(',')
### Check For Custom SALT
if([string]::IsNullOrEmpty($SALT) -eq $true) {
$SALT = $Realm
for($i=0;$i -lt $PrincipalArray.Count;$i++){
$SALT += $($PrincipalArray[$i].Replace('/',""))
}

}
### Finish spliting principal into component parts. PrincipalArray should have at most 2 elements. Testing with Java based tools, 
### the keytab entry can only support one UPN. The components portion of the keytab entry appears to only be for spliting
### a UPN in an SPN format. e.g. HOST/user@dev.home
$PrincipalText = $Principal
$Principal = $Principal.Replace('/',",")
$PrincipalArray = @()
$PrincipalArray = $Principal.Split(',')

[byte[]] $keyTabVersion = @(05,02)
[byte[]] $keyTabEntries = @()

### Set Default Encryption to AES256 if none of the E-Type switches are set
if(!$RC4 -and !$AES128 -and !$AES256){
$AES256 = $true
}

### Truncate KVNO
[Byte[]] $KVNO = [Byte[]](Get-BytesBigEndian -BitSize 32 -Value $KVNO)
[int16] $KVNO = [int]$KVNO[3]

### Create KeyTab Entries for selected E-Types RC4/AES128/AES256 supported
$keytabEntry = $null
if($RC4 -eq $true){
$keytabEntry = Create-KeyTabEntry `
-realmString $Realm -Components $PrincipalArray -passwordString $Password `
-PrincipalType $PType -EncryptionKeyType RC4 -KVNO $KVNO
$keyTabEntries += $keytabEntry.KeytabEntry
if($Script:Silent -eq $false){ Write-Host "RC4:"$keytabEntry.KeyBlock -ForegroundColor Cyan}
}
$keytabEntry = $null
if($AES128 -eq $true){
$keytabEntry = Create-KeyTabEntry `
-realmString $Realm -Components $PrincipalArray -passwordString $Password `
-PrincipalType $PType -EncryptionKeyType AES128 -KVNO $KVNO -SALT $SALT
$keyTabEntries += $keytabEntry.KeytabEntry
if($Script:Silent -eq $false){ Write-Host "AES128:"$keytabEntry.KeyBlock -ForegroundColor Cyan}
}
$keytabEntry = $null
if($AES256 -eq $true){
$keytabEntry = Create-KeyTabEntry `
-realmString $Realm -Components $PrincipalArray -passwordString $Password `
-PrincipalType $PType -EncryptionKeyType AES256 -KVNO $KVNO -SALT $SALT
$keyTabEntries += $keytabEntry.KeytabEntry
if($Script:Silent -eq $false){ Write-Host "AES256:"$keytabEntry.KeyBlock -ForegroundColor Cyan}
}

if($Script:Silent -eq $false){
Write-Host $("Principal Type:").PadLeft(15)$PType -ForegroundColor Green
Write-Host $("Realm:").PadLeft(15)$Realm -ForegroundColor Green
Write-Host $("User Name:").PadLeft(15)$PrincipalText -ForegroundColor Green
Write-Host $("SALT:").PadLeft(15)$SALT -ForegroundColor Green
Write-Host $("Keytab File:").PadLeft(15)$File -ForegroundColor Green
Write-Host $("Append File:").PadLeft(15)$Append -ForegroundColor Green
Write-Host ""
}

if(!$NoPrompt){
Write-Host "Press Enter to Write KeyTab File /Ctrl+C to quit..." -ForegroundColor Yellow -NoNewline
[void](Read-Host)
Write-Host ""
}

if($Append -eq $true){
$fileBytes = @()
    if([System.IO.File]::Exists($File)){
    $fileBytes += [System.IO.File]::ReadAllBytes($File) + $keyTabEntries
    [System.IO.File]::WriteAllBytes($File,$fileBytes)
    } else {
    $fileBytes = @()
    $fileBytes += $keyTabVersion
    $fileBytes += $keyTabEntries
    [System.IO.File]::WriteAllBytes($File,$fileBytes)
    }
} else {
$fileBytes = @()
$fileBytes += $keyTabVersion
$fileBytes += $keyTabEntries
[System.IO.File]::WriteAllBytes($File,$fileBytes)
}
