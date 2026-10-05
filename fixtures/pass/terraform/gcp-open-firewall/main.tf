resource "google_compute_firewall" "allow_ssh_iap" {
  name          = "allow-ssh-iap"
  network       = "default"
  source_ranges = ["35.235.240.0/20"]
  allow {
    protocol = "tcp"
    ports    = ["22"]
  }
}

resource "google_compute_firewall" "allow_rdp_internal" {
  name          = "allow-rdp-internal"
  network       = "default"
  source_ranges = ["10.0.0.0/8"]
  allow {
    protocol = "tcp"
    ports    = ["3389"]
  }
}

resource "google_compute_firewall" "allow_web_world" {
  name          = "allow-web-world"
  network       = "default"
  source_ranges = ["0.0.0.0/0"]
  allow {
    protocol = "tcp"
    ports    = ["80", "443"]
  }
}

resource "google_compute_firewall" "deny_ssh_world" {
  name          = "deny-ssh-world"
  network       = "default"
  source_ranges = ["0.0.0.0/0"]
  deny {
    protocol = "tcp"
    ports    = ["22", "3389"]
  }
}

resource "google_compute_firewall" "allow_app_port" {
  name          = "allow-app-port"
  network       = "default"
  source_ranges = ["0.0.0.0/0"]
  allow {
    protocol = "tcp"
    ports    = ["8080"]
  }
}

resource "google_compute_firewall" "allow_corp_admin" {
  name          = "allow-corp-admin"
  network       = "corp-vpc"
  source_ranges = ["192.168.1.0/24"]
  allow {
    protocol = "tcp"
    ports    = ["22"]
  }
}
