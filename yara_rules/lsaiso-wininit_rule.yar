rule ExternalLsaIsoRules
{
    condition:
        instance_count >= 0 and instance_count <= 1 and is_parent_valid and child_count == 0
}