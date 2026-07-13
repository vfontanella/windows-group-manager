<#
.SYNOPSIS
Creates, updates, renames, and removes Active Directory security groups from YAML configuration.

.DESCRIPTION
Prompts for a service account credential, reads settings.yaml and group YAML
files from the configured groups folder, then synchronizes security groups in
the configured OU.

Requires RSAT ActiveDirectory tools and the powershell-yaml module.
#>

#Requires -Version 5.1

[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [string]$SettingsPath,
    [string]$GroupsFolderPath
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

if ([string]::IsNullOrWhiteSpace($SettingsPath)) {
    $SettingsPath = Join-Path -Path $PSScriptRoot -ChildPath "settings.yaml"
}

function Import-RequiredModule {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Name
    )

    if (-not (Get-Module -ListAvailable -Name $Name)) {
        throw "Required PowerShell module '$Name' is not installed. On Windows Server, install it from an elevated PowerShell session. Example: Install-Module $Name -Scope AllUsers"
    }

    Import-Module $Name -ErrorAction Stop
}

function Read-YamlFile {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    if (-not (Test-Path -LiteralPath $Path)) {
        throw "YAML file not found: $Path"
    }

    $rawYaml = Get-Content -LiteralPath $Path -Raw
    if ([string]::IsNullOrWhiteSpace($rawYaml)) {
        throw "YAML file is empty: $Path"
    }

    return ConvertFrom-Yaml -Yaml $rawYaml
}

function Resolve-ConfiguredPath {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,

        [Parameter(Mandatory = $true)]
        [string]$BasePath
    )

    if ([System.IO.Path]::IsPathRooted($Path)) {
        return $Path
    }

    return Join-Path -Path $BasePath -ChildPath $Path
}

function Read-GroupDefinitionsFromFolder {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    if (-not (Test-Path -LiteralPath $Path -PathType Container)) {
        throw "Groups folder not found: $Path"
    }

    $groupFiles = @(
        Get-ChildItem -LiteralPath $Path -File |
            Where-Object { $_.Extension -in @(".yaml", ".yml") } |
            Sort-Object Name
    )

    if ($groupFiles.Count -eq 0) {
        throw "No group YAML files found in: $Path"
    }

    $groups = @()
    foreach ($groupFile in $groupFiles) {
        $groupDocument = Read-YamlFile -Path $groupFile.FullName
        $groupDefinitions = if ($null -ne (Get-OptionalValue -Object $groupDocument -Name "Group")) {
            @(Get-OptionalValue -Object $groupDocument -Name "Group")
        }
        elseif ($null -ne (Get-OptionalValue -Object $groupDocument -Name "Name")) {
            @($groupDocument)
        }
        elseif ($null -ne (Get-OptionalValue -Object $groupDocument -Name "Groups")) {
            @(Get-OptionalValue -Object $groupDocument -Name "Groups")
        }
        else {
            @($groupDocument)
        }

        $groups += ConvertTo-FlatGroupDefinitions -GroupDefinitions $groupDefinitions -SourceFile $groupFile.FullName -ParentGroupNames @()
    }

    return $groups
}

function ConvertTo-FlatGroupDefinitions {
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [object[]]$GroupDefinitions,

        [Parameter(Mandatory = $true)]
        [string]$SourceFile,

        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [string[]]$ParentGroupNames
    )

    $flatGroups = @()
    foreach ($groupDefinition in $GroupDefinitions) {
        if ($null -eq $groupDefinition) {
            continue
        }

        Set-ObjectValue -Object $groupDefinition -Name "SourceFile" -Value $SourceFile

        $configuredParentGroups = ConvertTo-StringArray -Value (Get-OptionalValue -Object $groupDefinition -Name "ParentGroups")
        $mergedParentGroups = @($configuredParentGroups + $ParentGroupNames | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | Select-Object -Unique)
        Set-ObjectValue -Object $groupDefinition -Name "ParentGroups" -Value $mergedParentGroups

        $flatGroups += $groupDefinition

        $childGroupsValue = Get-OptionalValue -Object $groupDefinition -Name "Groups"
        $childGroups = if ($null -ne $childGroupsValue) { @($childGroupsValue) } else { @() }
        if ($childGroups.Count -eq 0) {
            $childGroupsValue = Get-OptionalValue -Object $groupDefinition -Name "NestedGroups"
            $childGroups = if ($null -ne $childGroupsValue) { @($childGroupsValue) } else { @() }
        }

        $groupName = Get-OptionalValue -Object $groupDefinition -Name "Name"
        if ($childGroups.Count -gt 0 -and -not [string]::IsNullOrWhiteSpace([string]$groupName)) {
            $flatGroups += ConvertTo-FlatGroupDefinitions -GroupDefinitions $childGroups -SourceFile $SourceFile -ParentGroupNames @([string]$groupName)
        }
    }

    return $flatGroups
}

function Set-ObjectValue {
    param(
        [Parameter(Mandatory = $true)]
        [object]$Object,

        [Parameter(Mandatory = $true)]
        [string]$Name,

        [AllowNull()]
        [object]$Value
    )

    if ($Object -is [System.Collections.IDictionary]) {
        $Object[$Name] = $Value
        return
    }

    $Object | Add-Member -MemberType NoteProperty -Name $Name -Value $Value -Force
}

function Assert-RequiredValue {
    param(
        [Parameter(Mandatory = $true)]
        [AllowNull()]
        [object]$Value,

        [Parameter(Mandatory = $true)]
        [string]$Name
    )

    if ($null -eq $Value -or [string]::IsNullOrWhiteSpace([string]$Value)) {
        throw "Missing required value: $Name"
    }
}

function Get-OptionalValue {
    param(
        [Parameter(Mandatory = $true)]
        [object]$Object,

        [Parameter(Mandatory = $true)]
        [string]$Name
    )

    if ($Object -is [System.Collections.IDictionary]) {
        if ($Object.Contains($Name)) {
            return $Object[$Name]
        }

        return $null
    }

    $property = $Object.PSObject.Properties[$Name]
    if ($null -ne $property) {
        return $property.Value
    }

    return $null
}

function ConvertTo-Bool {
    param(
        [AllowNull()]
        [object]$Value,

        [bool]$Default = $false
    )

    if ($null -eq $Value) {
        return $Default
    }

    if ($Value -is [bool]) {
        return $Value
    }

    return [System.Convert]::ToBoolean([string]$Value)
}

function Escape-LdapFilterValue {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Value
    )

    return $Value.Replace("\", "\5c").Replace("*", "\2a").Replace("(", "\28").Replace(")", "\29").Replace("`0", "\00")
}

function ConvertTo-StringArray {
    param(
        [AllowNull()]
        [object]$Value
    )

    if ($null -eq $Value) {
        return @()
    }

    if ($Value -is [string]) {
        if ([string]::IsNullOrWhiteSpace($Value)) {
            return @()
        }

        return @([string]$Value)
    }

    $items = @()
    foreach ($item in @($Value)) {
        if ($null -ne $item -and -not [string]::IsNullOrWhiteSpace([string]$item)) {
            $items += [string]$item
        }
    }

    return $items
}

function Resolve-ADPrincipal {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Identity,

        [Parameter(Mandatory = $true)]
        [string]$DomainController,

        [Parameter(Mandatory = $true)]
        [pscredential]$Credential
    )

    $escapedIdentity = Escape-LdapFilterValue -Value $Identity
    $filter = "(|(distinguishedName=$escapedIdentity)(sAMAccountName=$escapedIdentity)(userPrincipalName=$escapedIdentity)(mail=$escapedIdentity)(cn=$escapedIdentity)(name=$escapedIdentity))"
    $matches = @(Get-ADObject -LDAPFilter $filter -Server $DomainController -Credential $Credential -Properties sAMAccountName,userPrincipalName,mail,objectClass)

    if ($matches.Count -eq 0) {
        throw "AD principal '$Identity' was not found by distinguishedName, sAMAccountName, userPrincipalName, mail, cn, or name."
    }

    if ($matches.Count -gt 1) {
        throw "AD principal '$Identity' matched more than one object. Use a unique distinguishedName, sAMAccountName, userPrincipalName, or mail value."
    }

    return $matches[0]
}

function Resolve-ADGroupByName {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Identity,

        [Parameter(Mandatory = $true)]
        [string]$DomainController,

        [Parameter(Mandatory = $true)]
        [pscredential]$Credential
    )

    $escapedIdentity = Escape-LdapFilterValue -Value $Identity
    $filter = "(|(distinguishedName=$escapedIdentity)(sAMAccountName=$escapedIdentity)(cn=$escapedIdentity)(name=$escapedIdentity))"
    $matches = @(Get-ADGroup -LDAPFilter $filter -Server $DomainController -Credential $Credential -Properties sAMAccountName)

    if ($matches.Count -eq 0) {
        throw "AD group '$Identity' was not found by distinguishedName, sAMAccountName, cn, or name."
    }

    if ($matches.Count -gt 1) {
        throw "AD group '$Identity' matched more than one group. Use a unique distinguishedName or sAMAccountName."
    }

    return $matches[0]
}

function Add-MissingGroupMembers {
    param(
        [Parameter(Mandatory = $true)]
        [object]$Group,

        [Parameter(Mandatory = $true)]
        [object[]]$Members,

        [Parameter(Mandatory = $true)]
        [string]$DomainController,

        [Parameter(Mandatory = $true)]
        [pscredential]$Credential
    )

    if ($Members.Count -eq 0) {
        return
    }

    $currentMemberDns = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($currentMember in @(Get-ADGroupMember -Identity $Group.DistinguishedName -Server $DomainController -Credential $Credential)) {
        $null = $currentMemberDns.Add($currentMember.DistinguishedName)
    }

    $membersToAdd = @()
    foreach ($member in $Members) {
        if (-not $currentMemberDns.Contains($member.DistinguishedName)) {
            $membersToAdd += $member.DistinguishedName
        }
    }

    if ($membersToAdd.Count -gt 0) {
        Add-ADGroupMember -Identity $Group.DistinguishedName -Members $membersToAdd -Server $DomainController -Credential $Credential
    }
}

function Read-ManagedGroupDatabase {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    if (-not (Test-Path -LiteralPath $Path)) {
        return [pscustomobject]@{ ManagedGroups = @() }
    }

    $rawJson = Get-Content -LiteralPath $Path -Raw
    if ([string]::IsNullOrWhiteSpace($rawJson)) {
        return [pscustomobject]@{ ManagedGroups = @() }
    }

    $database = $rawJson | ConvertFrom-Json
    if ($null -eq $database.ManagedGroups) {
        $database | Add-Member -MemberType NoteProperty -Name ManagedGroups -Value @()
    }

    return $database
}

function Save-ManagedGroupDatabase {
    param(
        [Parameter(Mandatory = $true)]
        [object]$Database,

        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    $parentPath = Split-Path -Path $Path -Parent
    if (-not [string]::IsNullOrWhiteSpace($parentPath) -and -not (Test-Path -LiteralPath $parentPath)) {
        New-Item -ItemType Directory -Path $parentPath -Force | Out-Null
    }

    $Database | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $Path -Encoding UTF8
}

function Upsert-ManagedGroupRecord {
    param(
        [Parameter(Mandatory = $true)]
        [object]$Database,

        [Parameter(Mandatory = $true)]
        [object]$Group
    )

    $records = @($Database.ManagedGroups | Where-Object { $_.SamAccountName -ine $Group.SamAccountName })
    $records += [ordered]@{
        Name = $Group.Name
        SamAccountName = $Group.SamAccountName
        DistinguishedName = $Group.DistinguishedName
        ObjectGuid = [string]$Group.ObjectGuid
        LastSeenUtc = [DateTime]::UtcNow.ToString("o")
    }

    $Database.ManagedGroups = @($records | Sort-Object SamAccountName)
}

function Remove-ManagedGroupRecord {
    param(
        [Parameter(Mandatory = $true)]
        [object]$Database,

        [Parameter(Mandatory = $true)]
        [string]$SamAccountName
    )

    $Database.ManagedGroups = @($Database.ManagedGroups | Where-Object { $_.SamAccountName -ine $SamAccountName })
}

function Resolve-ADUserByEmail {
    param(
        [Parameter(Mandatory = $true)]
        [string]$EmailAddress,

        [Parameter(Mandatory = $true)]
        [string]$DomainController,

        [Parameter(Mandatory = $true)]
        [pscredential]$Credential
    )

    $escapedEmail = $EmailAddress.Replace("'", "''")
    $filter = "mail -eq '$escapedEmail' -or userPrincipalName -eq '$escapedEmail'"

    return Get-ADUser -Filter $filter -Server $DomainController -Credential $Credential -Properties mail,userPrincipalName |
        Select-Object -First 1
}

Import-RequiredModule -Name ActiveDirectory
Import-RequiredModule -Name powershell-yaml

$credential = Get-Credential -Message "Enter the service account credentials used to manage Active Directory groups"
if ($null -eq $credential) {
    throw "Service account credentials are required."
}

$settingsDocument = Read-YamlFile -Path $SettingsPath
$settingsDirectory = Split-Path -Path (Resolve-Path -LiteralPath $SettingsPath) -Parent

Assert-RequiredValue -Value $settingsDocument.Settings.DomainController -Name "Settings.DomainController"
Assert-RequiredValue -Value $settingsDocument.Settings.TargetOU -Name "Settings.TargetOU"

$domainController = [string]$settingsDocument.Settings.DomainController
$targetOU = [string]$settingsDocument.Settings.TargetOU
$groupScopeValue = Get-OptionalValue -Object $settingsDocument.Settings -Name "GroupScope"
$removeMissingGroupsValue = Get-OptionalValue -Object $settingsDocument.Settings -Name "RemoveMissingGroups"
$managedDatabasePathValue = Get-OptionalValue -Object $settingsDocument.Settings -Name "ManagedDatabasePath"
$configuredGroupsFolderPathValue = Get-OptionalValue -Object $settingsDocument.Settings -Name "GroupsFolderPath"
$groupScope = if ($groupScopeValue) { [string]$groupScopeValue } else { "Global" }
$removeMissingGroups = ConvertTo-Bool -Value $removeMissingGroupsValue -Default $false
$managedDatabasePath = if ($managedDatabasePathValue) { [string]$managedDatabasePathValue } else { ".\managed-groups.json" }
$groupsFolderPath = if ($GroupsFolderPath) { $GroupsFolderPath } elseif ($configuredGroupsFolderPathValue) { [string]$configuredGroupsFolderPathValue } else { ".\groups" }

$managedDatabasePath = Resolve-ConfiguredPath -Path $managedDatabasePath -BasePath $settingsDirectory
$groupsFolderPath = Resolve-ConfiguredPath -Path $groupsFolderPath -BasePath $settingsDirectory
$groups = Read-GroupDefinitionsFromFolder -Path $groupsFolderPath

$desiredGroupNames = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
$previousGroupNames = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
$processedGroups = New-Object 'System.Collections.Hashtable' ([System.StringComparer]::OrdinalIgnoreCase)
$managedDatabase = Read-ManagedGroupDatabase -Path $managedDatabasePath
$databaseChanged = $false

$null = Get-ADOrganizationalUnit -Identity $targetOU -Server $domainController -Credential $credential

foreach ($group in $groups) {
    $sourceFile = Get-OptionalValue -Object $group -Name "SourceFile"
    $nameValue = Get-OptionalValue -Object $group -Name "Name"
    $descriptionValue = Get-OptionalValue -Object $group -Name "Description"
    $primaryOwnerValue = Get-OptionalValue -Object $group -Name "PrimaryOwner"
    $secondaryOwnerValue = Get-OptionalValue -Object $group -Name "SecondaryOwner"
    $contactEmailValue = Get-OptionalValue -Object $group -Name "ContactEmail"

    Assert-RequiredValue -Value $nameValue -Name "$sourceFile.Name"
    Assert-RequiredValue -Value $descriptionValue -Name "$sourceFile.Description"
    Assert-RequiredValue -Value $primaryOwnerValue -Name "$sourceFile.PrimaryOwner"
    Assert-RequiredValue -Value $secondaryOwnerValue -Name "$sourceFile.SecondaryOwner"
    Assert-RequiredValue -Value $contactEmailValue -Name "$sourceFile.ContactEmail"

    $name = [string]$nameValue
    $previousNameValue = Get-OptionalValue -Object $group -Name "PreviousName"
    $previousName = if ($previousNameValue) { [string]$previousNameValue } else { $null }
    $description = [string]$descriptionValue
    $primaryOwnerEmail = [string]$primaryOwnerValue
    $secondaryOwnerEmail = [string]$secondaryOwnerValue
    $contactEmail = [string]$contactEmailValue

    if (-not $desiredGroupNames.Add($name)) {
        throw "Duplicate group name '$name' found while loading group YAML files."
    }
    if (-not [string]::IsNullOrWhiteSpace($previousName)) {
        $null = $previousGroupNames.Add($previousName)
    }

    $primaryOwner = Resolve-ADUserByEmail -EmailAddress $primaryOwnerEmail -DomainController $domainController -Credential $credential
    if ($null -eq $primaryOwner) {
        throw "PrimaryOwner '$primaryOwnerEmail' for group '$name' was not found by mail or userPrincipalName."
    }

    $secondaryOwner = Resolve-ADUserByEmail -EmailAddress $secondaryOwnerEmail -DomainController $domainController -Credential $credential
    if ($null -eq $secondaryOwner) {
        throw "SecondaryOwner '$secondaryOwnerEmail' for group '$name' was not found by mail or userPrincipalName."
    }

    $notes = @(
        "PrimaryOwner: $primaryOwnerEmail"
        "SecondaryOwner: $secondaryOwnerEmail"
        "ContactEmail: $contactEmail"
    ) -join [Environment]::NewLine

    $escapedName = Escape-LdapFilterValue -Value $name
    $existingGroup = Get-ADGroup -LDAPFilter "(sAMAccountName=$escapedName)" -SearchBase $targetOU -SearchScope OneLevel -Server $domainController -Credential $credential -Properties mail,info,managedBy -ErrorAction SilentlyContinue

    if ($null -eq $existingGroup -and -not [string]::IsNullOrWhiteSpace($previousName)) {
        $escapedPreviousName = Escape-LdapFilterValue -Value $previousName
        $existingGroup = Get-ADGroup -LDAPFilter "(sAMAccountName=$escapedPreviousName)" -SearchBase $targetOU -SearchScope OneLevel -Server $domainController -Credential $credential -Properties mail,info,managedBy -ErrorAction SilentlyContinue

        if ($null -ne $existingGroup) {
            if ($PSCmdlet.ShouldProcess($previousName, "Rename security group to $name")) {
                Set-ADGroup `
                    -Identity $existingGroup.DistinguishedName `
                    -SamAccountName $name `
                    -Server $domainController `
                    -Credential $credential

                Rename-ADObject `
                    -Identity $existingGroup.DistinguishedName `
                    -NewName $name `
                    -Server $domainController `
                    -Credential $credential

                $existingGroup = Get-ADGroup -LDAPFilter "(sAMAccountName=$escapedName)" -SearchBase $targetOU -SearchScope OneLevel -Server $domainController -Credential $credential -Properties mail,info,managedBy
                Remove-ManagedGroupRecord -Database $managedDatabase -SamAccountName $previousName
                $databaseChanged = $true
            }
        }
    }

    if ($null -eq $existingGroup) {
        if ($PSCmdlet.ShouldProcess($name, "Create security group in $targetOU")) {
            New-ADGroup `
                -Name $name `
                -SamAccountName $name `
                -GroupCategory Security `
                -GroupScope $groupScope `
                -Description $description `
                -ManagedBy $primaryOwner.DistinguishedName `
                -Path $targetOU `
                -Server $domainController `
                -Credential $credential `
                -OtherAttributes @{ mail = $contactEmail; info = $notes }

            $existingGroup = Get-ADGroup -LDAPFilter "(sAMAccountName=$escapedName)" -SearchBase $targetOU -SearchScope OneLevel -Server $domainController -Credential $credential -Properties mail,info,managedBy
            Upsert-ManagedGroupRecord -Database $managedDatabase -Group $existingGroup
            $databaseChanged = $true
        }
    }
    else {
        if ($PSCmdlet.ShouldProcess($name, "Update security group properties")) {
            Set-ADGroup `
                -Identity $existingGroup.DistinguishedName `
                -Description $description `
                -ManagedBy $primaryOwner.DistinguishedName `
                -Server $domainController `
                -Credential $credential `
                -Replace @{ mail = $contactEmail; info = $notes }

            $existingGroup = Get-ADGroup -LDAPFilter "(sAMAccountName=$escapedName)" -SearchBase $targetOU -SearchScope OneLevel -Server $domainController -Credential $credential -Properties mail,info,managedBy
            Upsert-ManagedGroupRecord -Database $managedDatabase -Group $existingGroup
            $databaseChanged = $true
        }
    }

    if ($null -ne $existingGroup) {
        $processedGroups[$name] = $existingGroup
    }
}

foreach ($group in $groups) {
    $sourceFile = Get-OptionalValue -Object $group -Name "SourceFile"
    $name = [string](Get-OptionalValue -Object $group -Name "Name")
    $users = ConvertTo-StringArray -Value (Get-OptionalValue -Object $group -Name "Users")
    $members = @($users + (ConvertTo-StringArray -Value (Get-OptionalValue -Object $group -Name "Members")) | Select-Object -Unique)
    $parentGroups = ConvertTo-StringArray -Value (Get-OptionalValue -Object $group -Name "ParentGroups")

    if ($members.Count -eq 0 -and $parentGroups.Count -eq 0) {
        continue
    }

    $managedGroup = $processedGroups[$name]
    if ($null -eq $managedGroup) {
        $escapedName = Escape-LdapFilterValue -Value $name
        $managedGroup = Get-ADGroup -LDAPFilter "(sAMAccountName=$escapedName)" -SearchBase $targetOU -SearchScope OneLevel -Server $domainController -Credential $credential -Properties mail,info,managedBy -ErrorAction SilentlyContinue
    }

    if ($null -eq $managedGroup) {
        if ($WhatIfPreference) {
            Write-Warning "Skipping membership preview for '$name' because the group does not exist yet."
            continue
        }

        throw "Managed group '$name' was not found for membership updates."
    }

    $resolvedMembers = @()
    foreach ($memberIdentity in $members) {
        $resolvedMembers += Resolve-ADPrincipal -Identity $memberIdentity -DomainController $domainController -Credential $credential
    }

    if ($resolvedMembers.Count -gt 0) {
        if ($PSCmdlet.ShouldProcess($name, "Add configured members from $sourceFile")) {
            Add-MissingGroupMembers -Group $managedGroup -Members $resolvedMembers -DomainController $domainController -Credential $credential
        }
    }

    foreach ($parentGroupIdentity in $parentGroups) {
        $parentGroup = $processedGroups[$parentGroupIdentity]
        if ($null -eq $parentGroup) {
            try {
                $parentGroup = Resolve-ADGroupByName -Identity $parentGroupIdentity -DomainController $domainController -Credential $credential
            }
            catch {
                if ($WhatIfPreference) {
                    Write-Warning "Skipping nesting preview for '$name' because parent group '$parentGroupIdentity' was not found."
                    continue
                }

                throw
            }
        }

        if ($PSCmdlet.ShouldProcess($parentGroup.SamAccountName, "Nest $name as a member")) {
            Add-MissingGroupMembers -Group $parentGroup -Members @($managedGroup) -DomainController $domainController -Credential $credential
        }
    }
}

if ($removeMissingGroups) {
    foreach ($managedRecord in @($managedDatabase.ManagedGroups)) {
        if (-not $desiredGroupNames.Contains($managedRecord.SamAccountName) -and -not $previousGroupNames.Contains($managedRecord.SamAccountName)) {
            $managedGroup = $null
            if (-not [string]::IsNullOrWhiteSpace($managedRecord.ObjectGuid)) {
                $managedGroup = Get-ADGroup -Identity $managedRecord.ObjectGuid -Server $domainController -Credential $credential -Properties sAMAccountName -ErrorAction SilentlyContinue
            }

            if ($null -eq $managedGroup -and -not [string]::IsNullOrWhiteSpace($managedRecord.SamAccountName)) {
                $escapedManagedName = Escape-LdapFilterValue -Value $managedRecord.SamAccountName
                $managedGroup = Get-ADGroup -LDAPFilter "(sAMAccountName=$escapedManagedName)" -SearchBase $targetOU -SearchScope OneLevel -Server $domainController -Credential $credential -Properties sAMAccountName -ErrorAction SilentlyContinue
            }

            if ($null -eq $managedGroup) {
                if ($PSCmdlet.ShouldProcess($managedRecord.SamAccountName, "Remove stale managed group record from $managedDatabasePath")) {
                    Remove-ManagedGroupRecord -Database $managedDatabase -SamAccountName $managedRecord.SamAccountName
                    $databaseChanged = $true
                }

                continue
            }

            if (-not ([string]$managedGroup.DistinguishedName).EndsWith(",$targetOU", [System.StringComparison]::OrdinalIgnoreCase)) {
                Write-Warning "Skipping managed group '$($managedGroup.SamAccountName)' because it is no longer under Settings.TargetOU."
                continue
            }

            if ($PSCmdlet.ShouldProcess($managedGroup.SamAccountName, "Remove managed security group because it is missing from $groupsFolderPath")) {
                Remove-ADGroup `
                    -Identity $managedGroup.DistinguishedName `
                    -Server $domainController `
                    -Credential $credential `
                    -Confirm:$false

                Remove-ManagedGroupRecord -Database $managedDatabase -SamAccountName $managedRecord.SamAccountName
                $databaseChanged = $true
            }
        }
    }
}

if ($databaseChanged) {
    Save-ManagedGroupDatabase -Database $managedDatabase -Path $managedDatabasePath
}

Write-Host "Security group synchronization completed."
