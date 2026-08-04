package authz

import rego.v1

default allow := false

allow if {
    some role in data.user_roles[input.user]
    some perm in data.role_permissions[role]
    perm.action == input.action
    perm.resource == input.resource
}