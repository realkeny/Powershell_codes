<#
Script writen by Kehinde Adetutu (kadetutu@suffolk.com) - 11/08/2018

.DESCRIPTION
    Add users who are members of an AD (source) group to another AD (destination) group.
 
.PARAMETER Name
    Two mandatory parameters are requires (source and destination AD group names).
 
.EXAMPLE
    .\psAddUsersToGroupFromAnotherGroup.ps1 -s "_Apps_Citrix_Timberline" -d "Citrix_Okta_MFA"
 
.EXAMPLE
    .\psAddUsersToGroupFromAnotherGroup.ps1 -source "_Apps_Citrix_Timberline" -destination "Citrix_Okta_MFA"
 
#>

[CmdletBinding()]
Param(
	[Parameter(Mandatory=$True)]
	[alias("s","source")]
	[String]$source_group,
	
	[Parameter(Mandatory=$True)]
	[alias("d","destination")]
	[String]$destination_group	
)

if($source_group -ne "" -And $destination_group -ne "")
{
	Import-Module ActiveDirectory

	$src_group_users = @()
	$dst_group_users = @()

	Get-ADGroupmember $source_group | %{$src_group_users += (Get-ADUser $_).name}

	Get-ADGroupmember $destination_group | %{$dst_group_users += (Get-ADUser $_).name}

	$count = 0
	foreach($user in $src_group_users)
	{
		#write-host "checking $($user)..."
		if($dst_group_users -notcontains $user)
		{
			$count++
			write-host "Adding $($user) to $($destination_group)"
			$objUser = Get-ADUser -filter{name -eq $user}
			Add-ADGroupMember -Identity $destination_group -Members $objUser.samAccountName -Confirm:$False
		}
	}
	write-host "`n"
	write-host "Added $($count) users to $($destination_group)"
}
