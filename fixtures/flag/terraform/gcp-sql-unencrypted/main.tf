resource "google_sql_database_instance" "ssl_disabled" {
  name             = "db-ssl-disabled"
  database_version = "POSTGRES_15"
  settings {
    tier = "db-f1-micro"
    ip_configuration {
      require_ssl = false
    }
  }
}

resource "google_sql_database_instance" "open_authorized_block" {
  name             = "db-open-block"
  database_version = "MYSQL_8_0"
  settings {
    tier = "db-f1-micro"
    ip_configuration {
      require_ssl = true
      authorized_networks {
        name  = "internet"
        value = "0.0.0.0/0"
      }
    }
  }
}

resource "google_sql_database_instance" "ssl_disabled_open_ipv6" {
  name             = "db-ssl-disabled-ipv6"
  database_version = "POSTGRES_14"
  settings {
    tier = "db-f1-micro"
    ip_configuration {
      require_ssl = false
      authorized_networks {
        name  = "all-ipv6"
        value = "::/0"
      }
    }
  }
}

resource "google_sql_database_instance" "open_authorized_attr" {
  name             = "db-open-attr"
  database_version = "POSTGRES_15"
  settings {
    tier = "db-f1-micro"
    ip_configuration {
      require_ssl = true
      authorized_networks = [
        {
          name  = "world"
          value = "0.0.0.0/0"
        }
      ]
    }
  }
}
