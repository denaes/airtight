resource "google_storage_bucket_iam_binding" "public_viewer_binding" {
  bucket = "public-assets"
  role   = "roles/storage.objectViewer"
  members = [
    "allUsers",
  ]
}

resource "google_storage_bucket_iam_member" "public_viewer_member" {
  bucket = "public-assets"
  role   = "roles/storage.objectViewer"
  member = "allUsers"
}

resource "google_storage_bucket_iam_binding" "authenticated_binding" {
  bucket = "shared-docs"
  role   = "roles/storage.legacyBucketReader"
  members = [
    "allAuthenticatedUsers",
  ]
}

resource "google_storage_bucket_iam_member" "authenticated_member" {
  bucket = "shared-docs"
  role   = "roles/storage.objectAdmin"
  member = "allAuthenticatedUsers"
}
