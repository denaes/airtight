resource "azurerm_storage_account" "nested_public" {
  name                     = "storageaccountnested"
  resource_group_name      = "rg"
  location                 = "eastus"
  account_tier             = "Standard"
  account_replication_type = "LRS"
  allow_nested_items_to_be_public = true
}

resource "azurerm_storage_account" "public_net" {
  name                     = "storageaccountpubnet"
  resource_group_name      = "rg"
  location                 = "eastus"
  account_tier             = "Standard"
  account_replication_type = "LRS"
  public_network_access_enabled = true
}

resource "azurerm_storage_account" "both_public" {
  name                     = "storageaccountboth"
  resource_group_name      = "rg"
  location                 = "westeurope"
  account_tier             = "Standard"
  account_replication_type = "GRS"
  allow_nested_items_to_be_public = true
  public_network_access_enabled   = true
}

resource "azurerm_storage_account" "public_premium" {
  name                     = "storageaccountprem"
  resource_group_name      = "rg"
  location                 = "westus"
  account_tier             = "Premium"
  account_replication_type = "LRS"
  public_network_access_enabled = true
}
