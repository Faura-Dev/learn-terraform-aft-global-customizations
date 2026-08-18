# ---------------------------------------------------------------------------
# Fleet-wide IAM permissions boundary (pentest remediation: F-02)
# ---------------------------------------------------------------------------
# Creates the customer-managed policy `faura-permissions-boundary` in EVERY
# AFT-provisioned account. It is attached as the permissions boundary to every
# IAM role that Terraform (the github-oidc CI role or an SSO user) creates in
# faura-infra, and the deploy principals' own policies only allow
# CreateRole / PutRolePolicy / AttachRolePolicy / UpdateAssumeRolePolicy on
# roles that carry it. Together that separates "can deploy IAM" from "can
# grant itself admin": a deploy principal can still create and wire up roles,
# but every role it touches is capped by this boundary, and the boundary
# cannot be removed or edited by anyone operating under it.
#
# Ceiling design: broad Allow, then targeted Denies. The Denies are the
# control — they block the escalation primitives:
#   * human-identity backdoors (CreateUser + access key / login profile)
#   * detaching the boundary itself
#   * editing/deleting THIS policy to hollow it out
#   * creating or re-permissioning roles WITHOUT this boundary (so the
#     boundary propagates to everything a bounded principal creates)
#
# Rollout order matters (see faura-infra F-02 PRs):
#   1. Merge this — the policy must exist in every account first.
#   2. faura-infra phase 1: attach the boundary to all Terraform-managed roles.
#   3. faura-infra phase 2: gate the deploy principals' IAM writes on it.
# Deleting this policy while roles reference it breaks every deploy — treat
# it as load-bearing.

data "aws_caller_identity" "current" {}

locals {
  permissions_boundary_arn = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:policy/faura-permissions-boundary"
}

resource "aws_iam_policy" "permissions_boundary" {
  name        = "faura-permissions-boundary"
  description = "Permissions boundary for all Terraform-managed roles (pentest F-02). Do not delete: roles reference it."

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "AllowServiceWork"
        Effect   = "Allow"
        Action   = "*"
        Resource = "*"
      },
      {
        Sid    = "DenyHumanIdentityBackdoors"
        Effect = "Deny"
        Action = [
          "iam:CreateUser",
          "iam:CreateAccessKey",
          "iam:UpdateAccessKey",
          "iam:PutUserPolicy",
          "iam:AttachUserPolicy",
          "iam:CreateLoginProfile",
          "iam:UpdateLoginProfile",
          "iam:AddUserToGroup"
        ]
        Resource = "*"
      },
      {
        Sid    = "DenyBoundaryRemoval"
        Effect = "Deny"
        Action = [
          "iam:DeleteRolePermissionsBoundary",
          "iam:DeleteUserPermissionsBoundary"
        ]
        Resource = "*"
      },
      {
        Sid    = "DenyBoundaryPolicyTamper"
        Effect = "Deny"
        Action = [
          "iam:CreatePolicyVersion",
          "iam:DeletePolicy",
          "iam:DeletePolicyVersion",
          "iam:SetDefaultPolicyVersion"
        ]
        Resource = local.permissions_boundary_arn
      },
      {
        Sid    = "DenyUnboundedRoleWrites"
        Effect = "Deny"
        Action = [
          "iam:CreateRole",
          "iam:PutRolePolicy",
          "iam:AttachRolePolicy",
          "iam:UpdateAssumeRolePolicy",
          "iam:PutRolePermissionsBoundary"
        ]
        Resource = "*"
        Condition = {
          StringNotEquals = {
            "iam:PermissionsBoundary" = local.permissions_boundary_arn
          }
        }
      }
    ]
  })
}
