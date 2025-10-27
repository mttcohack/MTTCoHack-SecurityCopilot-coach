param (
    $region,
    $team
)
if ([string]::IsNullOrEmpty($region)) {
    Write-Error "The region parameter is required. Example: ./deploy-mt -region 'northeurope' -team '1'"
    exit 1
}
New-AzResourceGroup -Name "rg-hack-${team}" -Location $region -Tag @{SecurityControl="Ignore"; CostControl="Ignore"}
New-AzResourceGroupDeployment -Name co-hack-deployment-${team} -ResourceGroupName rg-hack-${team}  -TemplateFile co-hack-architecture-mt.bicep  -TemplateParameterFile co-hack-architecture.parameters-mt.json -team $team -location $region
