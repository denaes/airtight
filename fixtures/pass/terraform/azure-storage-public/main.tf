resource "azurerm_storage_account" "disabled_nested" {
  name                     = "storageaccountdisnested"
  resource_group_name      = "rg"
  location                 = "eastus"
  account_tier             = "Standard"
  account_replication_type = "LRS"
  allow_nested_items_to_be_public = false
}

resource "azurerm_storage_account" "disabled_public" {
  name                     = "storageaccountdispub"
  resource_group_name      = "rg"
  location                 = "eastus"
  account_tier             = "Standard"
  account_replication_type = "LRS"
  public_network_access_enabled = false
}

resource "azurerm_storage_account" "restricted_network" {
  name                     = "storageaccountrestr"
  resource_group_name      = "rg"
  location                 = "eastus"
  account_tier             = "Standard"
  account_replication_type = "LRS"
  public_network_access_enabled = true
  network_rules {
    default_action = "Deny"
    ip_rules       = ["198.51.100.1"]
  }
}

resource "azurerm_storage_account" "private_endpoints_only" {
  name                     = "storageaccountpriv"
  resource_group_name      = "rg"
  location                 = "westeurope"
  account_tier             = "Standard"
  account_replication_type = "LRS"
  network_rules {
    default_action             = "Deny"
    virtual_network_subnet_ids = ["/subscriptions/sub/resourceGroups/rg/providers/Microsoft.Network/virtualNetworks/vnet/subnets/s1"]
  }
}

resource "azurerm_storage_container" "private_container" {
  name                  = "content"
  storage_account_name  = "storageaccountdispub"
  container_access_type = "private"
}

resource "azurerm_storage_account" "clean_default" {
  name                     = "storageaccountclean"
  resource_group_name      = "rg"
  location                 = "eastus"
  account_tier             = "Standard"
  account_replication_type = "LRS"
}
