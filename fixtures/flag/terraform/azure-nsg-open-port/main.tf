resource "azurerm_network_security_rule" "open_ssh" {
  name                        = "allow-ssh-internet"
  priority                    = 100
  direction                   = "Inbound"
  access                      = "Allow"
  protocol                    = "Tcp"
  source_port_range           = "*"
  destination_port_range      = "22"
  source_address_prefix       = "*"
  destination_address_prefix  = "*"
  resource_group_name         = "rg-prod"
  network_security_group_name = "nsg-prod"
}

resource "azurerm_network_security_rule" "open_rdp" {
  name                        = "allow-rdp-internet"
  priority                    = 110
  direction                   = "Inbound"
  access                      = "Allow"
  protocol                    = "Tcp"
  source_port_range           = "*"
  destination_port_range      = "3389"
  source_address_prefix       = "0.0.0.0/0"
  destination_address_prefix  = "*"
  resource_group_name         = "rg-prod"
  network_security_group_name = "nsg-prod"
}

resource "azurerm_network_security_rule" "open_postgres" {
  name                        = "allow-pg-internet"
  priority                    = 120
  direction                   = "Inbound"
  access                      = "Allow"
  protocol                    = "Tcp"
  source_port_range           = "*"
  destination_port_range      = "5432"
  source_address_prefix       = "Internet"
  destination_address_prefix  = "*"
  resource_group_name         = "rg-prod"
  network_security_group_name = "nsg-prod"
}

resource "azurerm_network_security_rule" "open_multi_db" {
  name                        = "allow-databases-internet"
  priority                    = 130
  direction                   = "Inbound"
  access                      = "Allow"
  protocol                    = "Tcp"
  source_port_range           = "*"
  destination_port_ranges     = ["1433", "3306"]
  source_address_prefix       = "*"
  destination_address_prefix  = "*"
  resource_group_name         = "rg-prod"
  network_security_group_name = "nsg-prod"
}
