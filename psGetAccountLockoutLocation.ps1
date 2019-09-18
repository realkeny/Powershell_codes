<#
Script writen by Kehinde Adetutu (kenny.adetutu@gmail.com) - 9/18/2017

.DESCRIPTION
    This script parse security logs on specified Domain Controllers and collect logs related to account lockout. It then use
	the logs collected to display list of possible lockout locations. Microsoft LogParser library needs to be install on the host where
	this script is run.
 
.PARAMETER Names
    Username - logon name of user whose's lockout is being investigated.
	DCList - an array list of Domain Controller names to search for lockout logs.
 
.EXAMPLE
    .\psGetAccountLockoutLocation.ps1 -u kadetutu -dl DC01,DC02,DC03,DC04
 
.EXAMPLE
    .\psGetAccountLockoutLocation.ps1 -u kadetutu -dlist DC01,DC02,DC03,DC04
 
#>

[CmdletBinding()]
Param(
	[Parameter(Mandatory=$True,Position=1)]
	[alias("u")]
	[String]$username,
	
	[Parameter(Mandatory=$True,Position=2)]
	[alias("dl","dlist")]
	[String[]]$DCList
)

$objLp = New-object -com MSUtil.LogQuery
$objEvtIFormat = New-object -com MSUtil.LogQuery.EventLogInputFormat

#Declare some other variables to use.
$result_hash = @()
$failure_hash = @()

# Build a hash of error codes for the eventID.
$error_hash = @{
	"0x6" = "Bad username, or new computer/user account not replicated to DC yet.";
	"0x7" = "New Computer account has not yet replicated.";
	"0x12" = "Account disabled, expired or locked out.";
	"0x17" = "User's password has expired.";
	"0x18" = "Bad Password.";
	"0x25" = "Workstation's clock too far out of sync with DC's.";
	"0xC0000064" = "The specified user does not exists";
	"0xC000006A" = "Incorrect password entered";
	"0xC000006C" = "Password policy not met";
	"0xC000006D" = "Logon failed due to bad username";
	"0xC000006E" = "User account restriction prevented successful login";
	"0xC000006F" = "The User has time restriction for logon";
	"0xC0000070" = "User is restricted from login on from the source workstation";
	"0xC0000071" = "User's password has expired";
	"0xC0000072" = "The referenced account is currently disabled";
	"0xC000009A" = "Insufficient system resources";
	"0xC0000193" = "User's account has expired";
	"0xC0000224" = "User must change password before first time logon";
	"0xC0000234" = "User's account has been automatically locked";
	}

#Function to check error value and return corresponding error description.
Function GetErrorValue([String]$err_val)
{
	$desc = ""
	if($error_hash.ContainsKey($err_val))	#check if the error is listed in the $error_hash hash table.
	{
		$desc = $error_hash.get_item($err_val)
	}
	return $desc
}
	
#Function to extract correct IP address from the Strings field in Event log.
Function FormatLocation([String]$loc)
{
	$result = ""
	$arr = @()
	if($loc -ne "")
	{
		$arr = $loc.split(":")
		if($arr.count -gt 1)
		{
			$result = $arr[($arr.count)-1]
		}
		else
		{
			$result = $arr[0]
		}
	}
	return $result
}

#query for values in the security event logs on the servers (DCs) defined above.
foreach($server in $DCList)
{
	write-host "Searching for lockout on server: $($server)..."
	$path = "\\$server\Security"
	#generate list of logon failures with EventID 4771 (Kerberos authentication failures).
	$sql_4771 = "SELECT EXTRACT_TOKEN(Strings, 6, '|') AS Location, EXTRACT_TOKEN(Strings, 4, '|') AS Error, TimeGenerated FROM $path WHERE EXTRACT_TOKEN(Strings, 0, '|') = '$username' AND EventID='4771'"
	$rs = $objLp.Execute($sql_4771,$objEvtIFormat)
	if($rs)
	{
		for(; !$rs.atEnd(); $rs.moveNext())
		{
			$record = $rs.getRecord()
			$lock_origin = FormatLocation($record.Getvalue("Location").ToString())
			$error_reason = GetErrorValue($record.Getvalue("Error").ToString())
			#create a hash and store each values in the fields of $rs recordset.
			$hash = @{
				"Logon Source" = $lock_origin
				"Failure Date" = $record.Getvalue("TimeGenerated")
				"Failure Reason" = $error_reason
			}
			#create a powershell PSObject and set its property to the hash defined above.
			$Kerb_List = New-Object PSObject -Property $hash
			$result_hash += $Kerb_List	#add each PSObject to an array.
		}
	}
	#generate list of logon failures with EventID 4625 (NTLM authentication failures).
	$sql_4625 = "SELECT TimeGenerated ,EXTRACT_TOKEN(Strings,19,'|') AS Location,EXTRACT_TOKEN(Strings, 7, '|') AS Error ,EXTRACT_TOKEN(Strings, 9, '|') AS SubError FROM $path WHERE EXTRACT_TOKEN(Strings,5,'|') = '$username' AND EVENTID=4625"
	$rs = $objLp.Execute($sql_4625,$objEvtIFormat)
	if($rs)
	{
		for(; !$rs.atEnd(); $rs.moveNext())
		{
			$record = $rs.getRecord()
			$failure_source = FormatLocation($record.Getvalue("Location").ToString())
			$main_error = $record.Getvalue("Error").ToString()
			$sub_error = $record.Getvalue("SubError").ToString()
			if($main_error -eq "0xC0000234")
			{
				$the_error = $main_error
			}
			else
			{
				$the_error = $sub_error
			}
			$failure_reason = GetErrorValue($the_error)
			#create the hash for each field value.
			$hash_4625 = @{
				"Logon Source" = $failure_source
				"Failure Date" = $record.Getvalue("TimeGenerated")
				"Failure Reason" = $failure_reason
			}
			#create a powershell PSObject to store the hash values
			$NTLM_List = New-Object PSObject -Property $hash_4625
			$result_hash += $NTLM_List	#add each PSObject to an array.
		}
	}
	
	#generate list of logon failures with EventID 4776
	$sql_4776 = "SELECT TimeGenerated,EXTRACT_TOKEN(Strings,2,'|') AS Location,EXTRACT_TOKEN(Strings, 3, '|') AS Error FROM $path WHERE EXTRACT_TOKEN(Strings,1,'|') = '$username' AND  EVENTID=4776"
	$rs = $objLp.Execute($sql_4776,$objEvtIFormat)
	if($rs)
	{
		for(; !$rs.atEnd(); $rs.moveNext())
		{
			$record = $rs.getRecord()
			$failure_source = $record.Getvalue("Location").ToString()
			$failure_reason = GetErrorValue($record.Getvalue("Error").ToString())
			#create the hash to store each field value.
			$hash_4776 = @{
				"Logon Source" = $failure_source
				"Failure Date" = $record.Getvalue("TimeGenerated")
				"Failure Reason" = $failure_reason
			}
			#create a powershell PSObject to store the hash values
			$4776_List = New-Object PSObject -Property $hash_4776
			$result_hash += $4776_List	#add each PSObject to an array.
		}
	}
	
	#generate list of logon failures with EventID 4740
	$sql_4740 = "SELECT TimeGenerated,EXTRACT_TOKEN(Strings,2,'|') AS Location,EXTRACT_TOKEN(Strings, 3, '|') AS Error FROM $path WHERE EXTRACT_TOKEN(Strings,1,'|') = '$username' AND  EVENTID=4740"
	$rs = $objLp.Execute($sql_4740,$objEvtIFormat)
	if($rs)
	{
		for(; !$rs.atEnd(); $rs.moveNext())
		{
			$record = $rs.getRecord()
			$failure_source = $record.Getvalue("Location").ToString()
			$failure_reason = GetErrorValue($record.Getvalue("Error").ToString())
			#create the hash to store each field value.
			$hash_4740 = @{
				"Logon Source" = $failure_source
				"Failure Date" = $record.Getvalue("TimeGenerated")
				"Failure Reason" = $failure_reason
			}
			#create a powershell PSObject to store the hash values
			$4740_List = New-Object PSObject -Property $hash_4740
			$result_hash += $4740_List	#add each PSObject to an array.
		}
	}
}


#display result of the search for lockout on DCs here.
if($result_hash.count -le 0)
{
	write-host "`nThe search returned no result`n"
}	
else
{
	write-host "`nThe result of the search is displayed below: `n"
	$result_hash | format-table -Autosize | more
}
