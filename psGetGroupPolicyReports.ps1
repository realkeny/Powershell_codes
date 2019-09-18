 ## This script pull all suffolkconstruction.com domain group policcy report and export them to a CSV file.
 ## Writen by Kehinde Adetutu (kadetutu@suffolk.com) - 8/28/2019
function Get-GPOLink {
 
<#
.SYNOPSIS
    Returns the Active Directory (AD) Organization Units (OU's) that a Group Policy Object (GPO) is linked to.
 
.DESCRIPTION
    Get-GPOLink is a function that returns the Active Directory Organization Units (OU's) that a Group Policy
Object (GPO) is linked to.
 
.PARAMETER Name
    The Name of the Group Policy Object.
 
.EXAMPLE
    Get-GPOLink -Name 'Default Domain Policy'
 
.EXAMPLE
    Get-GPOLink -Name 'Default Domain Policy', 'Default Domain Controllers Policy'
 
.EXAMPLE
    'Default Domain Policy' | Get-GPOLink
 
.EXAMPLE
    'Default Domain Policy', 'Default Domain Controllers Policy' | Get-GPOLink
 
.EXAMPLE
    Get-GPO -All | Get-GPO-Link
 
.INPUTS
    System.String, Microsoft.GroupPolicy.Gpo
 
.OUTPUTS
    PSCustomObject
#>
 
    [CmdletBinding()]
    param (
        [Parameter(Mandatory,
                   ValueFromPipeline,
                   ValueFromPipelineByPropertyName)]
        [Alias('DisplayName')]
        [string[]]$Name
    )
 
    PROCESS {
 
        foreach ($n in $Name) {            
            $problem = $false
 
            try {
                Write-Verbose -Message "Attempting to produce XML report for GPO: $n"
 
                [xml]$report = Get-GPOReport -Name $n -ReportType Xml -ErrorAction Stop
            }
            catch {
                $problem = $true
                Write-Warning -Message "An error occured while attempting to query GPO: $n"
            }
 
            if (-not($problem)) {
                Write-Verbose -Message "Returning results for GPO: $n"
				
				$links_items = ""
				$links = $report.GPO.LinksTo
				foreach($link in $links)
				{
					
					$links_items += $link.SOMPath + "`n"
				}
				 
                [PSCustomObject]@{
                    'GPOName' = $report.GPO.Name
					
                    'Links Details' = $links_items
					'CreatedDate' = ([datetime]$report.GPO.CreatedTime).ToShortDateString()
                    'ModifiedDate' = ([datetime]$report.GPO.ModifiedTime).ToShortDateString()
                }
 
            }
 
        }
 
    }
 }
 Get-GPO -Domain Suffolkconstruction.com -All| Get-GPOLink | export-csv GPOResult2.csv