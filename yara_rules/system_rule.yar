rule ExternalSystemRules
{
    condition:
        instance_count == 1 and child_count == 1
}