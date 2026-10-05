resource "google_sql_database_instance" "ssl_enforced_private" {
  name             = "db-ssl-private"
  database_version = "POSTGRES_15"
  settings {
    tier = "db-f1-micro"
    ip_configuration {
      require_ssl = true
    }
  }
}

resource "google_sql_database_instance" "ssl_enforced_corp" {
  name             = "db-ssl-corp"
  database_version = "MYSQL_8_0"
  settings {
    tier = "db-f1-micro"
    ip_configuration {
      require_ssl = true
      authorized_networks {
        name  = "office"
        value = "192.168.1.0/24"
      }
    }
  }
}

resource "google_sql_database_instance" "internal_vpc_peering" {
  name             = "db-vpc-peering"
  database_version = "POSTGRES_14"
  settings {
    tier = "db-custom-2-7680"
    ip_configuration {
      ipv4_enabled    = false
      private_network = "projects/my-project/global/networks/default"
      require_ssl     = true
    }
  }
}

resource "google_sql_database_instance" "ssl_enforced_attr_list" {
  name             = "db-ssl-attr-list"
  database_version = "POSTGRES_15"
  settings {
    tier = "db-f1-micro"
    ip_configuration {
      require_ssl = true
      authorized_networks = [
        {
          name  = "bastion"
          value = "10.0.0.0/8"
        }
      ]
    }
  }
}

resource "google_sql_database_instance" "ssl_default_vpc" {
  name             = "db-ssl-default"
  database_version = "MYSQL_8_0"
  settings {
    tier = "db-f1-micro"
    ip_configuration {
      require_ssl = true
      authorized_networks {
        name  = "branch-office"
        value = "172.16.0.0/12"
      }
    }
  }
}

resource "google_compute_instance" "not_sql" {
  name         = "compute-instance"
  machine_type = "e2-medium"
  zone         = "us-central1-a"
}
