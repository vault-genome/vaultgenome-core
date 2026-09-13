# SPDX-License-Identifier: AGPL-3.0-or-later
#
# Provisions a GCP Confidential VM (AMD SEV-SNP) suitable for running
# the Vault Genome hardware-validation suite.
#
# Defaults are chosen to mirror the configuration we used for our Week 1
# sprint: N2D series, AMD SEV-SNP enabled at VMPL0, Ubuntu 24.04 LTS,
# 40 GB boot disk (large enough for Llama 3.2 3B + Ollama install +
# headroom), and full Cloud API access scope so the VM can read/write
# Cloud Storage for cross-region transfer tests.

terraform {
  required_version = ">= 1.5"
  required_providers {
    google = {
      source  = "hashicorp/google"
      version = ">= 5.0"
    }
  }
}

provider "google" {
  project = var.project_id
  region  = var.region
  zone    = var.zone
}

variable "project_id" {
  description = "GCP project to deploy into."
  type        = string
}

variable "region" {
  description = "GCP region. Must support N2D + AMD SEV-SNP Confidential VMs."
  type        = string
  default     = "us-central1"
}

variable "zone" {
  description = "GCP zone. Common choices: us-central1-a, us-central1-b, europe-west4-a."
  type        = string
  default     = "us-central1-a"
}

variable "instance_name" {
  description = "Name of the VM."
  type        = string
  default     = "vault-genome-sev-snp-test"
}

variable "machine_type" {
  description = "Machine type. n2d-standard-4 (4 vCPU, 16 GB) is the minimum we recommend."
  type        = string
  default     = "n2d-standard-4"
}

variable "disk_size_gb" {
  description = "Boot disk size. 40 GB is the minimum that fits Llama 3.2 3B + Ollama + headroom."
  type        = number
  default     = 40
}

resource "google_compute_instance" "vault_genome" {
  name         = var.instance_name
  machine_type = var.machine_type
  zone         = var.zone

  # AMD SEV-SNP Confidential VM. The actual SEV-SNP enablement happens
  # via the confidential_instance_config block + min_cpu_platform.
  confidential_instance_config {
    enable_confidential_compute = true
    confidential_instance_type  = "SEV_SNP"
  }

  # Confidential VMs require ON_HOST_MAINTENANCE = TERMINATE because
  # live migration is incompatible with memory encryption keys bound
  # to a specific physical socket.
  scheduling {
    on_host_maintenance = "TERMINATE"
  }

  shielded_instance_config {
    enable_secure_boot          = false # SEV-SNP firmware path doesn't always like Secure Boot
    enable_vtpm                 = true
    enable_integrity_monitoring = true
  }

  boot_disk {
    initialize_params {
      image = "projects/ubuntu-os-cloud/global/images/family/ubuntu-2404-lts-amd64"
      size  = var.disk_size_gb
      type  = "pd-balanced"
    }
  }

  network_interface {
    network = "default"
    access_config {
      # Ephemeral external IP — required for `gcloud compute ssh` and for
      # `apt install` / model download from public registries.
    }
  }

  service_account {
    # Use the project's default Compute service account, granted full
    # Cloud APIs scope. This is what makes `gcloud storage` work from
    # inside the VM without an extra `gcloud auth login` dance.
    scopes = ["cloud-platform"]
  }

  metadata = {
    enable-oslogin = "TRUE"
  }

  labels = {
    purpose = "vault-genome-hardware-validation"
    sprint  = "week-1-gcp-sev-snp"
  }
}

output "instance_name" {
  value = google_compute_instance.vault_genome.name
}

output "zone" {
  value = google_compute_instance.vault_genome.zone
}

output "external_ip" {
  value = google_compute_instance.vault_genome.network_interface[0].access_config[0].nat_ip
}

output "ssh_command" {
  value = "gcloud compute ssh ${google_compute_instance.vault_genome.name} --zone=${google_compute_instance.vault_genome.zone}"
}
