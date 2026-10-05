resource "google_compute_firewall" "allow_ssh_world" {
  name          = "allow-ssh-world"
  network       = "default"
  source_ranges = ["0.0.0.0/0"]
  allow {
    protocol = "tcp"
    ports    = ["22"]
  }
}

resource "google_compute_firewall" "allow_rdp_world" {
  name          = "allow-rdp-world"
  network       = "default"
  source_ranges = ["0.0.0.0/0"]
  allow {
    protocol = "tcp"
    ports    = ["3389"]
  }
}

resource "google_compute_firewall" "allow_ssh_ipv6" {
  name          = "allow-ssh-ipv6"
  network       = "default"
  source_ranges = ["::/0"]
  allow {
    protocol = "tcp"
    ports    = ["22"]
  }
}

resource "google_compute_firewall" "allow_multi_admin" {
  name          = "allow-multi-admin"
  network       = "vpc-prod"
  source_ranges = ["0.0.0.0/0"]
  allow {
    protocol = "tcp"
    ports    = ["80", "22", "443"]
  }
}
