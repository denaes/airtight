resource "azurerm_managed_disk" "disk_explicitly_disabled" {
  name                 = "disk-disabled"
  location             = "eastus"
  resource_group_name  = "rg"
  storage_account_type = "Standard_LRS"
  create_option        = "Empty"
  disk_size_gb         = 10
  encryption_settings {
    enabled = false
  }
}

resource "azurerm_managed_disk" "disk_missing_encryption" {
  name                 = "disk-missing"
  location             = "eastus"
  resource_group_name  = "rg"
  storage_account_type = "Standard_LRS"
  create_option        = "Empty"
  disk_size_gb         = 20
}

resource "azurerm_managed_disk" "disk_empty_encryption" {
  name                 = "disk-empty-settings"
  location             = "westeurope"
  resource_group_name  = "rg"
  storage_account_type = "Premium_LRS"
  create_option        = "Empty"
  disk_size_gb         = 50
  encryption_settings {}
}

resource "azurerm_managed_disk" "disk_ultra_missing" {
  name                 = "disk-ultra"
  location             = "eastus2"
  resource_group_name  = "rg"
  storage_account_type = "UltraSSD_LRS"
  create_option        = "Empty"
  disk_size_gb         = 100
}
