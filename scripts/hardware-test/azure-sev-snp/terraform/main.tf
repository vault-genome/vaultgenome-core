# SPDX-License-Identifier: AGPL-3.0-or-later
#
# Provisions an Azure Confidential VM (AMD SEV-SNP, DCasv5 series)
# suitable for running the Vault Genome hardware-validation suite.
#
# Defaults are chosen to mirror the configuration we used for our Week 3
# sprint: DCasv5 series, AMD SEV-SNP via Confidential VM, Ubuntu 22.04
# Confidential image (CVM SKU), 40 GB OS disk (large enough for
# Llama 3.2 3B + Ollama + headroom), managed identity for MAA token
# acquisition.

terraform {
  required_version = ">= 1.6"
  required_providers {
    azurerm = { source = "hashicorp/azurerm", version = "~> 4.0" }
    random  = { source = "hashicorp/random",  version = "~> 3.6" }
  }
}

provider "azurerm" {
  features {
    key_vault {
      purge_soft_delete_on_destroy    = true   # validation kit — clean teardown
      recover_soft_deleted_key_vaults = true
    }
  }
}

variable "location" {
  description = "Azure region (must support DCasv5 / DCadsv5)"
  type        = string
  default     = "eastus2"
}

variable "instance_name" {
  description = "Name of the VM"
  type        = string
  default     = "vault-genome-sev-snp-test"
}

variable "vm_size" {
  description = "VM size — DCasv5 (no local SSD) or DCadsv5 (local SSD); both are AMD SEV-SNP CVMs"
  type        = string
  default     = "Standard_DC4as_v5"
}

variable "admin_username" {
  description = "Linux admin user"
  type        = string
  default     = "azureuser"
}

variable "admin_ssh_public_key" {
  description = "SSH public key (read from ~/.ssh/id_ed25519.pub by default)"
  type        = string
}

variable "os_disk_size_gb" {
  description = "OS disk size — 40 GB is the minimum that fits Llama 3.2 3B + Ollama + headroom"
  type        = number
  default     = 40
}

# -----------------------------------------------------------------------------
# Resource group + network
# -----------------------------------------------------------------------------

resource "azurerm_resource_group" "validation" {
  name     = "${var.instance_name}-rg"
  location = var.location
  tags = {
    purpose = "vault-genome-hardware-validation"
    sprint  = "week-3-azure-sev-snp"
  }
}

resource "azurerm_virtual_network" "validation" {
  name                = "${var.instance_name}-vnet"
  location            = azurerm_resource_group.validation.location
  resource_group_name = azurerm_resource_group.validation.name
  address_space       = ["10.42.0.0/16"]
}

resource "azurerm_subnet" "validation" {
  name                 = "default"
  resource_group_name  = azurerm_resource_group.validation.name
  virtual_network_name = azurerm_virtual_network.validation.name
  address_prefixes     = ["10.42.1.0/24"]
}

# Public IP for SSH access to the validation VM
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
    source_address_prefix      = "*"  # validation kit only — restrict in production
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

# -----------------------------------------------------------------------------
# Managed identity (so the VM can request MAA JWT via az CLI)
# -----------------------------------------------------------------------------

resource "azurerm_user_assigned_identity" "validation" {
  name                = "${var.instance_name}-mi"
  location            = azurerm_resource_group.validation.location
  resource_group_name = azurerm_resource_group.validation.name
}

# -----------------------------------------------------------------------------
# Confidential VM (AMD SEV-SNP)
# -----------------------------------------------------------------------------

resource "azurerm_linux_virtual_machine" "validation" {
  name                  = var.instance_name
  location              = azurerm_resource_group.validation.location
  resource_group_name   = azurerm_resource_group.validation.name
  size                  = var.vm_size
  admin_username        = var.admin_username
  network_interface_ids = [azurerm_network_interface.validation.id]

  vtpm_enabled        = true
  secure_boot_enabled = true

  identity {
    type         = "UserAssigned"
    identity_ids = [azurerm_user_assigned_identity.validation.id]
  }

  admin_ssh_key {
    username   = var.admin_username
    public_key = var.admin_ssh_public_key
  }

  os_disk {
    name                     = "${var.instance_name}-os-disk"
    caching                  = "ReadWrite"
    storage_account_type     = "Premium_LRS"
    disk_size_gb             = var.os_disk_size_gb
    security_encryption_type = "VMGuestStateOnly"
  }

  source_image_reference {
    publisher = "Canonical"
    offer     = "0001-com-ubuntu-confidential-vm-jammy"
    sku       = "22_04-lts-cvm"
    version   = "latest"
  }

  tags = {
    purpose = "vault-genome-hardware-validation"
    sprint  = "week-3-azure-sev-snp"
  }
}

# -----------------------------------------------------------------------------
# Outputs
# -----------------------------------------------------------------------------

output "instance_name" {
  value = azurerm_linux_virtual_machine.validation.name
}

output "location" {
  value = azurerm_linux_virtual_machine.validation.location
}

output "public_ip" {
  value = azurerm_public_ip.validation.ip_address
}

output "ssh_command" {
  value = "ssh ${var.admin_username}@${azurerm_public_ip.validation.ip_address}"
}

output "managed_identity_id" {
  value = azurerm_user_assigned_identity.validation.id
}

output "resource_group" {
  value = azurerm_resource_group.validation.name
}
