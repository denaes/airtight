resource "azurerm_network_security_rule" "allow_ssh_internal" {
  name                        = "allow-ssh-internal"
  priority                    = 100
  direction                   = "Inbound"
  access                      = "Allow"
  protocol                    = "Tcp"
  source_port_range           = "*"
  destination_port_range      = "22"
  source_address_prefix       = "10.0.0.0/8"
  destination_address_prefix  = "*"
  resource_group_name         = "rg-prod"
  network_security_group_name = "nsg-prod"
}

resource "azurerm_network_security_rule" "allow_web_internet" {
  name                        = "allow-web-internet"
  priority                    = 110
  direction                   = "Inbound"
  access                      = "Allow"
  protocol                    = "Tcp"
  source_port_range           = "*"
  destination_port_range      = "443"
  source_address_prefix       = "*"
  destination_address_prefix  = "*"
  resource_group_name         = "rg-prod"
  network_security_group_name = "nsg-prod"
}

resource "azurerm_network_security_rule" "deny_ssh_internet" {
  name                        = "deny-ssh-internet"
  priority                    = 120
  direction                   = "Inbound"
  access                      = "Deny"
  protocol                    = "Tcp"
  source_port_range           = "*"
  destination_port_range      = "22"
  source_address_prefix       = "*"
  destination_address_prefix  = "*"
  resource_group_name         = "rg-prod"
  network_security_group_name = "nsg-prod"
}

resource "azurerm_network_security_rule" "outbound_ssh" {
  name                        = "allow-ssh-outbound"
  priority                    = 130
  direction                   = "Outbound"
  access                      = "Allow"
  protocol                    = "Tcp"
  source_port_range           = "*"
  destination_port_range      = "22"
  source_address_prefix       = "*"
  destination_address_prefix  = "*"
  resource_group_name         = "rg-prod"
  network_security_group_name = "nsg-prod"
}

resource "azurerm_network_security_rule" "allow_rdp_corp" {
  name                        = "allow-rdp-corp"
  priority                    = 140
  direction                   = "Inbound"
  access                      = "Allow"
  protocol                    = "Tcp"
  source_port_range           = "*"
  destination_port_range      = "3389"
  source_address_prefix       = "192.168.10.0/24"
  destination_address_prefix  = "*"
  resource_group_name         = "rg-prod"
  network_security_group_name = "nsg-prod"
}

resource "azurerm_network_security_rule" "allow_custom_app" {
  name                        = "allow-app-internet"
  priority                    = 150
  direction                   = "Inbound"
  access                      = "Allow"
  protocol                    = "Tcp"
  source_port_range           = "*"
  destination_port_range      = "8080"
  source_address_prefix       = "*"
  destination_address_prefix  = "*"
  resource_group_name         = "rg-prod"
  network_security_group_name = "nsg-prod"
}
