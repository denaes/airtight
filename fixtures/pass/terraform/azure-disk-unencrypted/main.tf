resource "azurerm_managed_disk" "disk_encryption_enabled" {
  name                 = "disk-enc-enabled"
  location             = "eastus"
  resource_group_name  = "rg"
  storage_account_type = "Standard_LRS"
  create_option        = "Empty"
  disk_size_gb         = 10
  encryption_settings {
    enabled = true
  }
}

resource "azurerm_managed_disk" "disk_cmk_des" {
  name                   = "disk-cmk"
  location               = "eastus"
  resource_group_name    = "rg"
  storage_account_type   = "Premium_LRS"
  create_option          = "Empty"
  disk_size_gb           = 50
  disk_encryption_set_id = "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg/providers/Microsoft.Compute/diskEncryptionSets/des1"
}

resource "azurerm_managed_disk" "disk_key_vault" {
  name                 = "disk-kv"
  location             = "westeurope"
  resource_group_name  = "rg"
  storage_account_type = "Standard_LRS"
  create_option        = "Empty"
  disk_size_gb         = 20
  encryption_settings {
    enabled = true
    disk_encryption_key {
      secret_url      = "https://myvault.vault.azure.net/secrets/mysecret/version"
      source_vault_id = "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg/providers/Microsoft.KeyVault/vaults/myvault"
    }
  }
}

resource "azurerm_managed_disk" "disk_des_var" {
  name                   = "disk-des-var"
  location               = "westus"
  resource_group_name    = "rg"
  storage_account_type   = "StandardSSD_LRS"
  create_option          = "Empty"
  disk_size_gb           = 30
  disk_encryption_set_id = var.disk_encryption_set_id
}

resource "azurerm_virtual_machine" "vm_not_managed_disk" {
  name                  = "vm-app"
  location              = "eastus"
  resource_group_name   = "rg"
  network_interface_ids = ["/subscriptions/xxx"]
  vm_size               = "Standard_DS1_v2"
}

resource "azurerm_managed_disk" "disk_both_des_and_enabled" {
  name                   = "disk-both"
  location               = "eastus"
  resource_group_name    = "rg"
  storage_account_type   = "Standard_LRS"
  create_option          = "Empty"
  disk_size_gb           = 10
  disk_encryption_set_id = "/subscriptions/xxx"
  encryption_settings {
    enabled = true
  }
}
