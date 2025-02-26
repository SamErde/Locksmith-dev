﻿function Write-PlatyPSDocs {
    <#
    .SYNOPSIS
    Use PlatyPS to create documentation for the current module.

    .DESCRIPTION
    This function uses PlatyPS to create documentation for the current module. It will generate markdown files for each
    function in the module, as well as a generic module page. Borrowing code from the Catesta module, by Jake Morrison
    (@techthoughts2), this script also checks for issues and missing information in the help documentation before creating
    an XML help file for online use.

    .EXAMPLE
    Write-PlatyPSDocs

    Does what it says on the tin.
    - Create markdown docs from comment-based help in each exported function.
    - Create a general markdown page for the module.
    - Create XML-based external help files for the module.

    #>
    [CmdletBinding()]
    param ()

    $ModuleName = 'Locksmith'
    $ModulePath = Split-Path -Path $PSScriptRoot -Parent

    # Remove the module from the current session to ensure we are working with the current source version.
    Remove-Module -Name $ModuleName -Force -ErrorAction SilentlyContinue

    # Get the path to the module manifest.
    $ModuleManifestPath = Join-Path -Path $PSScriptRoot -ChildPath "..\${ModuleName}.psd1"

    try {
        Import-Module ServerManager -Force -ErrorAction SilentlyContinue -WarningAction SilentlyContinue | Out-Null
        Import-Module $ModuleManifestPath -Force
        $ModuleInfo = Test-ModuleManifest -Path $ModuleManifestPath
    } catch {
        throw "Failed to import module manifest at $ModuleManifestPath. $_"
    }

    # Get module details from manifest
    $ModuleVersion = $ModuleInfo.Version
    $ModuleDescription = $ModuleInfo.Description
    $FunctionsToExport = $ModuleInfo.ExportedFunctions

    # Prepare parameters for New-MarkdownHelp
    $DocsFolder = Join-Path -Path $ModulePath -ChildPath 'Docs'
    $ModulePage = Join-Path -Path $DocsFolder -ChildPath "$($ModuleName).md"
    $markdownParams = @{
        Module         = $ModuleName
        OutputFolder   = $DocsFolder
        Force          = $true
        WithModulePage = $true
        ModulePagePath = $ModulePage
        Locale         = 'en-US'
        FwLink         = 'NA'
        HelpVersion    = $ModuleVersion
        Encoding       = [System.Text.Encoding]::UTF8
    }

    # Generate markdown help files
    New-MarkdownHelp @markdownParams | Out-Null


    # Fixes and cleanup for markdown files #


    # Fix formatting in multiline examples
    Get-ChildItem -Path $DocsFolder -Recurse -File | ForEach-Object {
        $Content = Get-Content $_.FullName -Raw
        $NewContent = $Content -replace '(## EXAMPLE [^`]+?```\r\n[^`\r\n]+?\r\n)(```\r\n\r\n)([^#]+?\r\n)(\r\n)([^#]+)(#)', '$1$3$2$4$5$6'
        if ($NewContent -ne $content) {
            Set-Content -Path $_.FullName -Value $NewContent -Force
        }
    }

    # Repair markdown files generated by PlatyPS in PowerShell 7.4
    . $ModulePath\Build\MarkdownRepair.ps1
    $DocsFolder | Get-ChildItem -File | ForEach-Object {
        Repair-PlatyPSMarkdown -Path $_.FullName
    }

    # Replace each missing element we need for a proper generic module page .md file
    $ModulePageFileContent = Get-Content -Raw $ModulePage
    $ModulePageFileContent = $ModulePageFileContent -replace '{{ Fill in the Description }}', $ModuleDescription
    $ModulePageFileContent | Out-File $ModulePage -Force -Encoding:utf8

    # Replace each missing element we need for a proper function .md file
    $FunctionsToExport | ForEach-Object {
        $TextToReplace = "{{ Manually Enter $($_) Description Here }}"
        $ReplacementText = (Get-Help -Detailed $_).Synopsis
        $ModulePageFileContent = $ModulePageFileContent -replace $TextToReplace, $ReplacementText
    }
    $ModulePageFileContent | Out-File $ModulePage -Force -Encoding:utf8

    # Check for missing or invalid  GUID
    $MissingGUID = Select-String -Path "$DocsFolder\*.md" -Pattern '(00000000-0000-0000-0000-000000000000)'
    if ($MissingGUID.Count -gt 0) {
        Write-Host 'The documentation that got generated resulted in a generic GUID. Check the GUID entry of your module manifest.' -ForegroundColor Yellow
        throw 'Missing GUID. Please review and rebuild.'
    }

    # Check for missing sections in markdown files
    Write-Host 'Checking for missing documentation in MD files...' -ForegroundColor Gray
    $MissingDocumentation = Select-String -Path "$DocsFolder\*.md" -Pattern '({{.*}})'
    if ($MissingDocumentation.Count -gt 0) {
        Write-Host 'The documentation that got generated resulted in missing sections which should be filled out. Please review the following sections in your comment based help, fill out missing information and rerun this build.' -ForegroundColor Yellow
        Write-Host "(Note: This can happen if the .EXTERNALHELP CBH is defined for a function before running this build.)`n" -ForegroundColor Yellow
        Write-Host "Path of files with issues: $DocsFolder\" -ForegroundColor Yellow
        $MissingDocumentation | Select-Object FileName, LineNumber, Line | Format-Table -AutoSize
        Write-Warning -Message 'Missing documentation. Please review and rebuild.'
    }

    Write-Host 'Checking for missing SYNOPSIS in MD files...' -ForegroundColor Gray
    $fSynopsisOutput = @()
    $synopsisEval = Select-String -Path "$DocsFolder\*.md" -Pattern '^## SYNOPSIS$' -Context 0, 1
    $synopsisEval | ForEach-Object {
        $chAC = $_.Context.DisplayPostContext.ToCharArray()
        if ($null -eq $chAC) {
            $fSynopsisOutput += $_.FileName
        }
    }
    if ($fSynopsisOutput) {
        Write-Host 'The following files are missing SYNOPSIS:' -ForegroundColor Yellow
        $fSynopsisOutput
        throw 'SYNOPSIS information missing. Please review.'
    }


    Write-Host 'Markdown generation complete.' -ForegroundColor Gray

    # Build the external xml help file from markdown help files with PlatyPS
    Write-Host 'Creating external xml help file...' -ForegroundColor Gray
    $null = New-ExternalHelp "$DocsFolder" -OutputPath "$PSScriptRoot\..\en-US\" -Force -Encoding ([System.Text.Encoding]::UTF8)
    Write-Host '...External xml help file created!' -ForegroundColor Gray


    # Create a CAB file for the external help
    $params = @{
        CabFilesFolder  = Join-Path -Path $PSScriptRoot -ChildPath '..\en-US'
        LandingPagePath = Join-Path -Path $PSScriptRoot -ChildPath '..\Docs\Locksmith.md'
        OutputFolder    = Join-Path -Path $PSScriptRoot -ChildPath '..\en-US'
    }
    New-ExternalHelpCab @params


} # end function Write-PlatyPSDocs

Write-PlatyPSDocs
