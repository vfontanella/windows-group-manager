# Windows Security Group Manager

PowerShell script for creating, updating, renaming, and removing Active Directory security groups from YAML files on Windows Server.

## Windows Server Requirements

- Windows Server 2016 or newer.
- Windows PowerShell 5.1 or PowerShell 7.
- Network access to the configured domain controller.
- RSAT Active Directory PowerShell module installed.
- `powershell-yaml` PowerShell module installed.
- A service account with permissions to create, update, rename, and remove groups in the configured target OU.

## Recommended Windows Folder Layout

Install the application under a fixed Windows path such as:

```text
C:\Scripts\WindowsGroupManager\
C:\Scripts\WindowsGroupManager\Manage-SecurityGroups.ps1
C:\Scripts\WindowsGroupManager\settings.yaml
C:\Scripts\WindowsGroupManager\managed-groups.json
C:\Scripts\WindowsGroupManager\groups\finance.yaml
C:\Scripts\WindowsGroupManager\groups\hr.yaml
C:\Scripts\WindowsGroupManager\groups\engineering.yaml
```

## Install Prerequisites

Run PowerShell as Administrator on the Windows Server.

Install the Active Directory PowerShell module:

```powershell
Install-WindowsFeature RSAT-AD-PowerShell -IncludeAllSubFeature
```

Install the YAML parser module:

```powershell
Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force
Install-Module powershell-yaml -Scope AllUsers -Force
```

If the server blocks script execution, allow local scripts:

```powershell
Set-ExecutionPolicy RemoteSigned -Scope LocalMachine
```

## Create Folders

```powershell
New-Item -ItemType Directory -Path 'C:\Scripts\WindowsGroupManager' -Force
New-Item -ItemType Directory -Path 'C:\Scripts\WindowsGroupManager\groups' -Force
```

Place these files in `C:\Scripts\WindowsGroupManager`:

```text
Manage-SecurityGroups.ps1
settings.yaml
managed-groups.json
```

Place group YAML files in:

```text
C:\Scripts\WindowsGroupManager\groups
```

## settings.yaml

Use absolute Windows paths on servers so the script works no matter which directory PowerShell starts in.

```yaml
Settings:
  DomainController: dc01.mydomain.com
  TargetOU: OU=MyOrg,OU=Managed Groups,DC=MyDomain,DC=com
  GroupScope: Global
  RemoveMissingGroups: true
  ManagedDatabasePath: 'C:\Scripts\WindowsGroupManager\managed-groups.json'
  GroupsFolderPath: 'C:\Scripts\WindowsGroupManager\groups'
```

## managed-groups.json

Create the file with an empty managed group inventory:

```json
{
  "ManagedGroups": []
}
```

This file is the safety database. The script only deletes AD groups that are already recorded here and still located under `Settings.TargetOU`.

## Group Files

Create one YAML file per team or group under `C:\Scripts\WindowsGroupManager\groups`.

Example: `C:\Scripts\WindowsGroupManager\groups\finance.yaml`

```yaml
Name: SG-FIN-READERS
PreviousName: SG-FINANCE-READERS
Description: Finance Readers
PrimaryOwner: john.smith@mydomain.com
SecondaryOwner: jane.doe@mydomain.com
ContactEmail: finance-access@mydomain.com
Users:
  - alice.jones@mydomain.com
  - bob.wilson@mydomain.com
Members:
  - SG-FIN-ANALYSTS
ParentGroups:
  - SG-FIN-ALL
Groups:
  - Name: SG-FIN-APPROVERS
    Description: Finance Approvers
    PrimaryOwner: john.smith@mydomain.com
    SecondaryOwner: jane.doe@mydomain.com
    ContactEmail: finance-approvers@mydomain.com
    Users:
      - approver.one@mydomain.com
```

The filename is for organization only. The AD group name comes from `Name` inside the YAML file.

`Users` is optional. Use it to add users to the group. Each value can be a unique `sAMAccountName`, `userPrincipalName`, email address, common name, object name, or distinguished name.

`Members` is optional. Use it to add other AD principals, such as groups, computers, or service accounts. User entries also continue to work in `Members`.

`ParentGroups` is optional. Use it to nest this managed group inside one or more parent AD groups.

`Groups` is optional. Use it to define child groups inside the current group. The child groups are created as managed groups and automatically nested into their parent group. `NestedGroups` is also accepted as an alias.

## Run The Script

Preview changes first:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File 'C:\Scripts\WindowsGroupManager\Manage-SecurityGroups.ps1' -SettingsPath 'C:\Scripts\WindowsGroupManager\settings.yaml' -WhatIf
```

Apply changes:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File 'C:\Scripts\WindowsGroupManager\Manage-SecurityGroups.ps1' -SettingsPath 'C:\Scripts\WindowsGroupManager\settings.yaml'
```

The script prompts for the service account username and password each time it starts.

## Behavior

- Creates missing security groups in `Settings.TargetOU`.
- Updates existing groups matched by `sAMAccountName`.
- Renames groups when `PreviousName` is set and the current `Name` is not found.
- Records managed groups in `ManagedDatabasePath` after successful create, update, or rename operations.
- Adds configured `Users` to the managed group without removing existing members.
- Adds configured `Members` to the managed group without removing existing members.
- Adds the managed group into each configured `ParentGroups` parent group for nested group membership.
- Creates child groups from nested `Groups` or `NestedGroups` YAML sections and nests each child group inside its parent group.
- Removes only groups already recorded in `ManagedDatabasePath`, still located under `Settings.TargetOU`, when `RemoveMissingGroups` is `true` and they are not listed in any YAML file under `GroupsFolderPath`.
- Sets `description` from `Description`.
- Sets `managedBy` to the resolved `PrimaryOwner` user.
- Stores `PrimaryOwner`, `SecondaryOwner`, and `ContactEmail` in the group's notes field.
- Sets the group's `mail` attribute to `ContactEmail`.

## Rename Groups

To rename a group, change `Name` to the new value and set `PreviousName` to the current AD group name:

```yaml
Name: SG-FIN-READERS
PreviousName: SG-FINANCE-READERS
Description: Finance Readers
PrimaryOwner: john.smith@mydomain.com
SecondaryOwner: jane.doe@mydomain.com
ContactEmail: finance-access@mydomain.com
```

After the rename has been applied successfully, remove `PreviousName` from the YAML file.

## Add Members

Add users to a managed group with `Users`:

```yaml
Name: SG-FIN-READERS
Description: Finance Readers
PrimaryOwner: john.smith@mydomain.com
SecondaryOwner: jane.doe@mydomain.com
ContactEmail: finance-access@mydomain.com
Users:
  - alice.jones@mydomain.com
  - bob.wilson@mydomain.com
```

Add groups, computers, service accounts, or mixed principals with `Members`:

```yaml
Name: SG-FIN-READERS
Description: Finance Readers
PrimaryOwner: john.smith@mydomain.com
SecondaryOwner: jane.doe@mydomain.com
ContactEmail: finance-access@mydomain.com
Members:
  - SG-FIN-ANALYSTS
  - CN=svc-finance,OU=Service Accounts,DC=MyDomain,DC=com
```

The script adds missing users and members only. It does not remove members that are absent from `Users` or `Members`.

## Nested Groups

Nest the managed group inside existing parent groups with `ParentGroups`:

```yaml
Name: SG-FIN-READERS
Description: Finance Readers
PrimaryOwner: john.smith@mydomain.com
SecondaryOwner: jane.doe@mydomain.com
ContactEmail: finance-access@mydomain.com
ParentGroups:
  - SG-FIN-ALL
  - SG-APP-ERP-USERS
```

This makes `SG-FIN-READERS` a member of each listed parent group. Parent groups can be existing AD groups or groups managed by this application.

Create child groups inside a managed group with `Groups`:

```yaml
Name: SG-FIN-ALL
Description: All Finance Access
PrimaryOwner: john.smith@mydomain.com
SecondaryOwner: jane.doe@mydomain.com
ContactEmail: finance-access@mydomain.com
Groups:
  - Name: SG-FIN-READERS
    Description: Finance Readers
    PrimaryOwner: john.smith@mydomain.com
    SecondaryOwner: jane.doe@mydomain.com
    ContactEmail: finance-readers@mydomain.com
    Users:
      - alice.jones@mydomain.com
  - Name: SG-FIN-APPROVERS
    Description: Finance Approvers
    PrimaryOwner: john.smith@mydomain.com
    SecondaryOwner: jane.doe@mydomain.com
    ContactEmail: finance-approvers@mydomain.com
    Users:
      - approver.one@mydomain.com
```

This creates `SG-FIN-ALL`, `SG-FIN-READERS`, and `SG-FIN-APPROVERS`, then adds each child group as a member of `SG-FIN-ALL`.

## Remove Groups Safely

Set `RemoveMissingGroups: true` in `settings.yaml` to remove groups from `Settings.TargetOU` when their YAML file is deleted from `GroupsFolderPath`.

Deletion is intentionally limited to groups recorded in `managed-groups.json` and still located under `Settings.TargetOU`. Groups that exist in the OU but were never created, updated, or renamed by this script are not removed.

Always preview removals first:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File 'C:\Scripts\WindowsGroupManager\Manage-SecurityGroups.ps1' -SettingsPath 'C:\Scripts\WindowsGroupManager\settings.yaml' -WhatIf
```
