targetScope = 'subscription'

@description('The location for the resources deployed in this solution.')
param location string = deployment().location

@description('The suffix to be added to the deployment name.')
param deploymentNameSuffix string = utcNow()

@description('The name of the resource group.')
param resourceGroupName string = 'rg-acr-${uniqueString(deployment().name)}'

@description('The name of the service principal.')
param spName string

@description('The password for the service principal.')
@secure()
param spPassword string

@description('The client ID for the Falcon API.')
param falconClientId string

@description('The client secret for the Falcon API.')
@secure()
param falconClientSecret string

param subscriptionId string

// variables for the deployment
var automationAccountName = 'aa-acr-${uniqueString(rg.id)}'
var cloud = environment().name
var tenantId = tenant().tenantId
// var subscriptionId = subscription().subscriptionId
var psFalconUri = 'https://www.powershellgallery.com/api/v2/package/PSFalcon/2.2.7'
var psFalconVersion = '2.2.7'
var runbook = [
  {
    name: 'New-AzureContainerRegistration.ps1'
    uri: 'https://raw.githubusercontent.com/mikedzikowski/OnBoardAzureContainerRegistryUsingPsFalconApi/refs/heads/main/runbooks/New-AzureContainerRegistration.ps1'
  }
]
var arcPullRoleId = '7f951dda-4ed3-4680-a7ca-43fe172d538d'
var keyVaultSecretReaderRoleId = '4633458b-17de-408a-b874-0445c86b69e6'
var azureReaderRoleId = 'acdd72a7-3385-48ef-bd42-f606fba81ae7'

resource rg 'Microsoft.Resources/resourceGroups@2024-03-01' = {
  name: resourceGroupName
  location: location
}

module keyVault 'modules/keyVault.bicep' = { 
  name: 'keyvault-deployment-${deploymentNameSuffix}'
  scope: resourceGroup(rg.name)
  params: {
    keyVaultName: 'kv-acr-${uniqueString(rg.id)}'
    spName: spName
    spPassword: spPassword
    falconClientId:falconClientId
    falconClientSecret:falconClientSecret
  }
}

module automationAccount 'modules/automationaccount.bicep' = {
  name: 'automationaccount-deployment-${deploymentNameSuffix}'
  scope: resourceGroup(rg.name)
  params: {
    automationAccountName: automationAccountName
    location: location
    psFalconUri: psFalconUri
    psFalconVersion: psFalconVersion
    runbookNames: runbook
    environment: cloud
    keyVaultName: keyVault.outputs.keyVaultName
    subscriptionId: subscriptionId
    tenantId: tenantId
  }
}

module readerRoleAutomationAccount 'modules/rbacPermissions.bicep' = {
  name: 'rbac-readerRole-${deploymentNameSuffix}'
  params: {
    principalId: automationAccount.outputs.aaIdentityId
    roleId: azureReaderRoleId
    scope: subscriptionId
  }
}

module arcPullRoleAutomationAccount 'modules/rbacPermissions.bicep' = {
  name: 'rbac-arcPullRole-${deploymentNameSuffix}'
  params: {
    principalId: automationAccount.outputs.aaIdentityId
    roleId: arcPullRoleId
    scope: subscriptionId
  }
}

module keyVaultSecretReaderAutomationAccount 'modules/roleAssignmentKeyVault.bicep' = {
  name: 'rbac-keyVaultSecretReaderRole-${deploymentNameSuffix}'
  scope: resourceGroup(resourceGroupName)
  params: {
    identityPrincipalId: automationAccount.outputs.aaIdentityId
    keyVaultName: keyVault.outputs.keyVaultName
    roleDefinitionId: keyVaultSecretReaderRoleId
  }
}
