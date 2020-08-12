rule ExternalSvcHostExeRules
{
    condition:
        instance_count >= 10 and is_parent_valid and child_count <= 2
}