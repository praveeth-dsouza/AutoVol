rule ExternalWinLogOnExeRules
{
    condition:
        instance_count >= 1 and is_parent_valid and child_count >= 0
}