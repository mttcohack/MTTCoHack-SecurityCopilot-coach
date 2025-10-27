

param location string = 'northeurope'
param VnetName string = 'Hack-vnet' 

param HackVmName string = 'hack-vm'
param HackVmPipName string = 'hack-vm-pip' 
param HackVmNicName string = 'hack-vm-nic' 
param HackVmNsgName string = 'hack-vm-nsg'
param HackVmAdminUsername string = 'hacker'
@secure()
param HackVmAdminPassword string 

param WorkstationVmName string = 'workstation-vm'
param WorkstationVmNicName string = 'workstation-vm-nic' 
param DcVmNsgName string = 'dc-vm-nsg'
param WorkstationVmAdminUsername string = 'johnson'
@secure()
param WorkstationVmAdminPassword string

param WorkstationVmPrivateIPAddress string = '10.0.0.100'
param ScriptUrl string

param DcVmName string = 'dc-vm'
param DcVmNicName string = 'dc-vm-nic' 
param DcVmAdminUsername string = 'dcadmin'
@secure()
param DcVmAdminPassword string
param DcVmPrivateIPAddress string = '10.0.1.250'

param domainName string = 'contoso.com'
param domainJoinOptions int = 3

param _artifactsLocation string 

@secure()
param _artifactsLocationSasToken string 

resource virtualNetwork 'Microsoft.Network/virtualNetworks@2019-11-01' = {
  name: VnetName
  location: location
  properties: {
    addressSpace: {
      addressPrefixes: [
        '10.0.0.0/16'
      ]
    }
    subnets: [
      {
        name: 'external-subnet'
        properties: {
          addressPrefix: '10.0.0.0/24'
        }
      }
      {
        name: 'internal-subnet'
        properties: {
          addressPrefix: '10.0.1.0/24'
        }
      }
    ]
  }
}

resource HackVmPublicIP 'Microsoft.Network/publicIPAddresses@2021-02-01' = {
  name: HackVmPipName
  location: location
  properties: {
    publicIPAllocationMethod: 'Static'
  }
}

resource HackVmNetworkSecurityGroup 'Microsoft.Network/networkSecurityGroups@2019-11-01' = {
  name: HackVmNsgName
  location: location
  properties: {
    securityRules: [
      {
        name: 'AllowRdp'
        properties: {
          description: 'description'
          protocol: 'Tcp'
          sourcePortRange: '*'
          destinationPortRange: '3389'
          sourceAddressPrefix: '*'
          destinationAddressPrefix: '*'
          access: 'Allow'
          priority: 100
          direction: 'Inbound'
        }
      }
    ]
  }
}

resource HackVmNetworkInterface 'Microsoft.Network/networkInterfaces@2021-02-01' = {
  name: HackVmNicName
  location: location
  dependsOn: [
    virtualNetwork
    HackVmNetworkSecurityGroup
    HackVmPublicIP    
  ]
  properties: {
    ipConfigurations: [
      {
        name: 'myIPConfig'
        properties: {
          subnet: {
            id: resourceId('Microsoft.Network/virtualNetworks/subnets', VnetName, 'external-subnet')
          }
          publicIPAddress: {
            id: resourceId('Microsoft.Network/publicIPAddresses', HackVmPipName)
          }
        }
      }
    ]
    networkSecurityGroup: {
      id: resourceId('Microsoft.Network/networkSecurityGroups', HackVmNsgName)
    }
  }
}

resource HackVmNameWindows10 'Microsoft.Compute/virtualMachines@2020-12-01' = {
  name: HackVmName
  location: location
  dependsOn: [
    HackVmNetworkInterface
  ]
  properties: {
    hardwareProfile: {
      vmSize: 'Standard_B2s'
    }
    osProfile: {
      computerName: HackVmName
      adminUsername: HackVmAdminUsername
      adminPassword: HackVmAdminPassword
      windowsConfiguration: {
        enableAutomaticUpdates: true
        provisionVMAgent: true
      }
    }
    storageProfile: {
      imageReference: {
        publisher: 'MicrosoftWindowsDesktop'
        offer: 'Windows-10'
        sku: 'win10-21h2-pro-g2'
        version: 'latest'
      }
      osDisk: {
        name: HackVmName
        caching: 'ReadWrite'
        createOption: 'FromImage'
      }
    }
    networkProfile: {
      networkInterfaces: [
        {
          id: resourceId('Microsoft.Network/networkInterfaces', HackVmNicName)
        }
      ]
    }
    diagnosticsProfile: {
      bootDiagnostics: {
        enabled: false
      }
    }
    licenseType: 'Windows_Client'
  }
}

resource DcVmNetworkSecurityGroup 'Microsoft.Network/networkSecurityGroups@2019-11-01' = {
  name: DcVmNsgName
  location: location
  properties: {
    securityRules: [
      {
        name: 'Allowall'
        properties: {
          description: 'description'
          protocol: '*'
          sourcePortRange: '*'
          destinationPortRange: '*'
          sourceAddressPrefix: '10.0.0.100'
          destinationAddressPrefix: '*'
          access: 'Allow'
          priority: 100
          direction: 'Inbound'
        }
      }
      {
        name: 'DenyVnet'
        properties: {
          description: 'description'
          protocol: '*'
          sourcePortRange: '*'
          destinationPortRange: '*'
          sourceAddressPrefix: 'VirtualNetwork'
          destinationAddressPrefix: 'VirtualNetwork'
          access: 'Deny'
          priority: 200
          direction: 'Inbound'
        }
      }
    ]
  }
}
resource DcVmNetworkInterface 'Microsoft.Network/networkInterfaces@2021-02-01' = {
  name: DcVmNicName
  location: location
  dependsOn: [
    virtualNetwork
  ]
  properties: {
    ipConfigurations: [
      {
        name: 'myIPConfig'
        properties: {
          privateIPAllocationMethod: 'Static'
          privateIPAddress: DcVmPrivateIPAddress
          subnet: {
            id: resourceId('Microsoft.Network/virtualNetworks/subnets', VnetName, 'internal-subnet')
          }
        }
      }
    ]
    networkSecurityGroup: {
      id: resourceId('Microsoft.Network/networkSecurityGroups', DcVmNsgName)
    }
  }
}

resource DcWindows2016 'Microsoft.Compute/virtualMachines@2020-12-01' = {
  name: DcVmName
  location: location
  dependsOn: [
    DcVmNetworkInterface
  ]
  properties: {
    hardwareProfile: {
      vmSize: 'Standard_B2s'
    }
    osProfile: {
      computerName: DcVmName
      adminUsername: DcVmAdminUsername
      adminPassword: DcVmAdminPassword
    }
    storageProfile: {
      imageReference: {
        publisher: 'MicrosoftWindowsServer'
        offer: 'WindowsServer'
        sku: '2016-Datacenter'
        version: 'latest'
      }
      osDisk: {
        name: DcVmName
        caching: 'ReadWrite'
        createOption: 'FromImage'
      }
      dataDisks: [
        {
          name: '${DcVmName}_DataDisk'
          caching: 'ReadWrite'
          createOption: 'Empty'
          diskSizeGB: 20
          managedDisk: {
            storageAccountType: 'StandardSSD_LRS'
          }
          lun: 0
        }
      ]
    }
    networkProfile: {
      networkInterfaces: [
        {
          id: resourceId('Microsoft.Network/networkInterfaces', DcVmNicName)
        }
      ]
    }
    diagnosticsProfile: {
      bootDiagnostics: {
        enabled: false
      }
    }
  }
}

resource virtualMachineName_CreateADForest 'Microsoft.Compute/virtualMachines/extensions@2022-03-01' = {
  parent: DcWindows2016
  name: 'CreateADForest'
  location: location
  properties: {
    publisher: 'Microsoft.Powershell'
    type: 'DSC'
    typeHandlerVersion: '2.19'
    autoUpgradeMinorVersion: true
    settings: {
      ModulesUrl: 'https://raw.githubusercontent.com/mttcohack/MTTCoHack-SecurityCopilot-coach/main/CreateADPDC.ps1'
      
      ConfigurationFunction: 'CreateADPDC.ps1\\CreateADPDC'
      Properties: {
        DomainName: domainName
        AdminCreds: {
          UserName: DcVmAdminUsername
          Password: 'PrivateSettingsRef:AdminPassword'
        }
      }
    }
    protectedSettings: {
      Items: {
        AdminPassword: DcVmAdminPassword
      }
    }
  }
}

resource DisableRestrictedAdminextension 'Microsoft.Compute/virtualMachines/extensions@2021-11-01' = {
  parent: DcWindows2016
  name:'DisableRestrictedAdmin'
  location:location
  properties:{
    publisher: 'Microsoft.Compute'
    type:'CustomScriptExtension'
    typeHandlerVersion: '1.10'
    autoUpgradeMinorVersion: true
    protectedSettings:{
      commandToExecute: 'powershell -command "New-ItemProperty -Path "HKLM:\\System\\CurrentControlSet\\Control\\Lsa" -Name "DisableRestrictedAdmin" -Value "0" -PropertyType DWORD -Force"'
    }
  }
}

resource WorkstationVmNetworkInterface 'Microsoft.Network/networkInterfaces@2021-02-01' = {
  name: WorkstationVmNicName
  location: location
  dependsOn: [
    virtualNetwork
  ]
  properties: {
    ipConfigurations: [
      {
        name: 'myIPConfig'
        properties: {
          privateIPAllocationMethod: 'Static'
          privateIPAddress: WorkstationVmPrivateIPAddress
          subnet: {
            id: resourceId('Microsoft.Network/virtualNetworks/subnets', VnetName, 'external-subnet')
          }
         
        }
      }
    ]
    dnsSettings: {
      dnsServers: [DcVmPrivateIPAddress]
    }
  }
}

resource WorkstationVmWindows10 'Microsoft.Compute/virtualMachines@2020-12-01' = {
  name: WorkstationVmName
  location: location
  dependsOn: [
    WorkstationVmNetworkInterface
    DcWindows2016
    virtualMachineName_CreateADForest
    HackVmNameWindows10
  ]
  properties: {
    hardwareProfile: {
      vmSize: 'Standard_B2s'
    }
    osProfile: {
      computerName: WorkstationVmName
      adminUsername: WorkstationVmAdminUsername
      adminPassword: WorkstationVmAdminPassword
      windowsConfiguration: {
        enableAutomaticUpdates: true
        provisionVMAgent: true
      }
    }
    storageProfile: {
      imageReference: {
        publisher: 'MicrosoftWindowsDesktop'
        offer: 'Windows-10'
        sku: 'win10-21h2-pro-g2'
        version: 'latest'
      }
      osDisk: {
        name: WorkstationVmName
        caching: 'ReadWrite'
        createOption: 'FromImage'
      }
    }
    networkProfile: {
      networkInterfaces: [
        {
          id: resourceId('Microsoft.Network/networkInterfaces', WorkstationVmNicName)
        }
      ]
    }
    diagnosticsProfile: {
      bootDiagnostics: {
        enabled: false
      }
    }
    licenseType: 'Windows_Client'
  }
}

resource virtualMachineExtension 'Microsoft.Compute/virtualMachines/extensions@2021-03-01' = {
  parent: WorkstationVmWindows10
  name: 'joindomain'
  location: location
  dependsOn: [
   virtualMachineName_CreateADForest
  ]
  properties: {
    publisher: 'Microsoft.Compute'
    type: 'JsonADDomainExtension'
    typeHandlerVersion: '1.3'
    autoUpgradeMinorVersion: true
    settings: {
      name: domainName
      ouPath: ''
      user: '${domainName}\\${DcVmAdminUsername}'
      restart: true
      options: domainJoinOptions
    }
    protectedSettings: {
      Password: DcVmAdminPassword
    }
  }
}

resource lockoutthresholdextension 'Microsoft.Compute/virtualMachines/extensions@2021-11-01' = {
  parent: HackVmNameWindows10
  name:'lockoutthreshold'
  location:location
  dependsOn: [
    virtualMachineExtension
   ]
  properties:{
    publisher: 'Microsoft.Compute'
    type:'CustomScriptExtension'
    typeHandlerVersion: '1.10'
    autoUpgradeMinorVersion: true
    protectedSettings:{
      fileUris: [ScriptUrl]
      commandToExecute: 'powershell.exe -ExecutionPolicy Unrestricted -File script-workstation.ps1'
    }
    
  }
}

output IPAddress string = HackVmPublicIP.properties.ipAddress
output Login string = HackVmAdminUsername
output Password string = HackVmAdminPassword

