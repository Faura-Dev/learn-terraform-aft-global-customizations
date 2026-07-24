# ---------------------------------------------------------------------------
# Account-level IMDSv2 default (pentest remediation: IMDSv1 available)
# ---------------------------------------------------------------------------
# Sets the region-level Instance Metadata Service default for EVERY
# AFT-provisioned account. New EC2 instances launched without an explicit
# metadata_options block inherit these values, closing the "account default
# does not require IMDSv2" finding.
#
# Scope / caveats:
#   * Applies only to NEWLY launched instances. Existing running instances are
#     NOT modified — fix those at the instance level in faura-infra (or via
#     `aws ec2 modify-instance-metadata-options`).
#   * This is a DEFAULT, not hard enforcement. Instance-level metadata_options
#     still win (e.g. langfuse in faura-infra pins hop_limit = 2 because it runs
#     containers on the host that need IMDS — that override is preserved).
#   * hop_limit = 1 is safe here: all Faura ECS is Fargate (no EC2 container
#     hosts that reach IMDS through an extra network hop). Any future
#     EC2-backed container host must set its own metadata_options.
#   * Region-scoped. If accounts run workloads outside the AFT provider region,
#     replicate this resource per region with aliased providers.
#
# Requires AWS provider >= 5.43.0 (resource introduced there). If the AFT
# pipeline pins an older provider, add a required_providers constraint.
resource "aws_ec2_instance_metadata_defaults" "imdsv2" {
  http_tokens                 = "required"
  http_endpoint               = "enabled"
  http_put_response_hop_limit = 1
}
