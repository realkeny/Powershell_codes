<#
Script writen by Kehinde Adetutu (kadetutu@suffolk.com) - 7/25/2019

.DESCRIPTION
    Add users who are members of an AD (source) group from another AD (destination) group.
 
.PARAMETER Name
    Two mandatory parameters are requires (source and destination AD group names).
 
.EXAMPLE
    .\psRemoveUsersInOneGroupFromAnotherGroup.ps1 -s "_Apps_Citrix_Timberline" -d "Citrix_Okta_MFA"
 
.EXAMPLE
    .\psRemoveUsersInOneGroupFromAnotherGroup.ps1 -source "_Apps_Citrix_Timberline" -destination "Citrix_Okta_MFA"
 
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
		if($dst_group_users -contains $user)
		{
			$count++
			write-host "Removing $($user) from $($destination_group)"
			$objUser = Get-ADUser -filter{name -eq $user}
			Remove-ADGroupMember -Identity $destination_group -Members $objUser.samAccountName -Confirm:$False
		}
	}
	write-host "`n"
	write-host "Removed $($count) users from $($destination_group)"
}
