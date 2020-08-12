rule ExternalCrssRules
{
    condition:
        instance_count >=2 and is_parent_valid and child_count == 0
}