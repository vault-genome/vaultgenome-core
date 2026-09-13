# SPDX-License-Identifier: AGPL-3.0-or-later
#
# Provisions an Azure DCsv3 SGX VM suitable for running the Vault
# Genome hardware-validation suite (Intel SGX track).

terraform {
  required_version = ">= 1.6"
  required_providers {
    azurerm = { source = "hashicorp/azurerm", version = "~> 4.0" }
  }
}

provider "azurerm" {
  features {}
}

variable "location" {
  description = "Azure region (must support DCsv3)"
  type        = string
  default     = "eastus2"
}

variable "instance_name" {
  description = "Name of the VM"
  type        = string
  default     = "vault-genome-sgx-test"
}

variable "vm_size" {
  description = "VM size — DCsv3 series for Intel SGX"
  type        = string
  default     = "Standard_DC4s_v3"
}

variable "admin_username" {
  description = "Linux admin user"
  type        = string
  default     = "azureuser"
}

variable "admin_ssh_public_key" {
  description = "SSH public key"
  type        = string
}

variable "os_disk_size_gb" {
  description = "OS disk size"
  type        = number
  default     = 40
}

# -----------------------------------------------------------------------------
# Network
# -----------------------------------------------------------------------------

resource "azurerm_resource_group" "validation" {
  name     = "${var.instance_name}-rg"
  location = var.location
  tags = {
    purpose = "vault-genome-hardware-validation"
    sprint  = "week-3-azure-sgx"
  }
}

resource "azurerm_virtual_network" "validation" {
  name                = "${var.instance_name}-vnet"
  location            = azurerm_resource_group.validation.location
  resource_group_name = azurerm_resource_group.validation.name
  address_space       = ["10.43.0.0/16"]
}

resource "azurerm_subnet" "validation" {
  name                 = "default"
  resource_group_name  = azurerm_resource_group.validation.name
  virtual_network_name = azurerm_virtual_network.validation.name
  address_prefixes     = ["10.43.1.0/24"]
}

resource "azurerm_public_ip" "validation" {
  name                = "${var.instance_name}-ip"
  location            = azurerm_resource_group.validation.location
  resource_group_name = azurerm_resource_group.validation.name
  allocation_method   = "Static"
  sku                 = "Standard"
}

resource "azurerm_network_security_group" "validation" {
  name                = "${var.instance_name}-nsg"
  location            = azurerm_resource_group.validation.location
  resource_group_name = azurerm_resource_group.validation.name
  security_rule {
    name                       = "ssh"
    priority                   = 100
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_range     = "22"
    source_address_prefix      = "*"
    destination_address_prefix = "*"
  }
}

resource "azurerm_network_interface" "validation" {
  name                = "${var.instance_name}-nic"
  location            = azurerm_resource_group.validation.location
  resource_group_name = azurerm_resource_group.validation.name
  ip_configuration {
    name                          = "ipconfig"
    subnet_id                     = azurerm_subnet.validation.id
    private_ip_address_allocation = "Dynamic"
    public_ip_address_id          = azurerm_public_ip.validation.id
  }
}

resource "azurerm_network_interface_security_group_association" "validation" {
  network_interface_id      = azurerm_network_interface.validation.id
  network_security_group_id = azurerm_network_security_group.validation.id
}

resource "azurerm_user_assigned_identity" "validation" {
  name                = "${var.instance_name}-mi"
  location            = azurerm_resource_group.validation.location
  resource_group_name = azurerm_resource_group.validation.name
}

# -----------------------------------------------------------------------------
# DCsv3 VM (Intel SGX)
# -----------------------------------------------------------------------------

resource "azurerm_linux_virtual_machine" "validation" {
  name                  = var.instance_name
  location              = azurerm_resource_group.validation.location
  resource_group_name   = azurerm_resource_group.validation.name
  size                  = var.vm_size
  admin_username        = var.admin_username
  network_interface_ids = [azurerm_network_interface.validation.id]

  identity {
    type         = "UserAssigned"
    identity_ids = [azurerm_user_assigned_identity.validation.id]
  }

  admin_ssh_key {
    username   = var.admin_username
    public_key = var.admin_ssh_public_key
  }

  os_disk {
    name                 = "${var.instance_name}-os-disk"
    caching              = "ReadWrite"
    storage_account_type = "Premium_LRS"
    disk_size_gb         = var.os_disk_size_gb
  }

  source_image_reference {
    publisher = "Canonical"
    offer     = "0001-com-ubuntu-server-jammy"
    sku       = "22_04-lts-gen2"
    version   = "latest"
  }

  tags = {
    purpose = "vault-genome-hardware-validation"
    sprint  = "week-3-azure-sgx"
  }
}

# -----------------------------------------------------------------------------
# Outputs
# -----------------------------------------------------------------------------

output "instance_name"      { value = azurerm_linux_virtual_machine.validation.name }
output "location"           { value = azurerm_linux_virtual_machine.validation.location }
output "public_ip"          { value = azurerm_public_ip.validation.ip_address }
output "ssh_command"        { value = "ssh ${var.admin_username}@${azurerm_public_ip.validation.ip_address}" }
output "managed_identity_id" { value = azurerm_user_assigned_identity.validation.id }
output "resource_group"     { value = azurerm_resource_group.validation.name }
