resource "google_storage_bucket_iam_member" "user_viewer" {
  bucket = "private-bucket"
  role   = "roles/storage.objectViewer"
  member = "user:alice@example.com"
}

resource "google_storage_bucket_iam_binding" "group_viewer" {
  bucket = "team-bucket"
  role   = "roles/storage.objectViewer"
  members = [
    "group:developers@example.com",
  ]
}

resource "google_storage_bucket_iam_member" "service_account_admin" {
  bucket = "app-bucket"
  role   = "roles/storage.objectAdmin"
  member = "serviceAccount:my-sa@my-project.iam.gserviceaccount.com"
}

resource "google_storage_bucket_iam_binding" "domain_binding" {
  bucket = "internal-bucket"
  role   = "roles/storage.legacyBucketReader"
  members = [
    "domain:company.internal",
  ]
}

resource "google_storage_bucket" "secure_bucket" {
  name     = "isolated-storage"
  location = "US"
  uniform_bucket_level_access = true
}

resource "google_storage_bucket_iam_member" "scoped_reader" {
  bucket = "private-bucket"
  role   = "roles/storage.legacyObjectReader"
  member = "user:bob@example.com"
}
