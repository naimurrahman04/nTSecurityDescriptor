# Your Base64 Security Descriptor
$base64 = "AQAEgBQAAAAA..."

# Convert to binary
$bytes = [Convert]::FromBase64String($base64)

# Parse the descriptor
$sd = New-Object System.Security.AccessControl.RawSecurityDescriptor -ArgumentList ($bytes, 0)

# Dump the ACL entries
$sd.DiscretionaryAcl | ForEach-Object {
    [PSCustomObject]@{
        SID         = $_.SecurityIdentifier.Value
        Right       = $_.AccessMask
        AceType     = $_.AceType
        AceFlags    = $_.AceFlags
        Inherited   = $_.IsInherited
    }
}
