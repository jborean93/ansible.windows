#!powershell

# Copyright: (c) 2026, Ansible Project
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

#AnsibleRequires -CSharpUtil Ansible.Basic
#AnsibleRequires -CSharpUtil ..module_utils._TaskScheduler

using namespace ansible_collections.ansible.windows.plugins.module_utils._TaskScheduler
using namespace System.Globalization
using namespace System.Security.Principal

filter Format-Enum {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory, ValueFromPipeline)]
        [int]
        $InputObject,

        [Parameter(Position = 0, Mandatory)]
        [Type]$EnumType,

        [Parameter(Position = 1)]
        [string]$Prefix
    )

    # Enum.ToObject does not throw an exception if the enum does not have a
    # value for the input integer.
    $enumVal = [Enum]::ToObject($EnumType, $InputObject)
    $rawType = [Enum]::GetUnderlyingType($EnumType)

    $rawStrings = if ($EnumType.IsDefined([FlagsAttribute], $false)) {
        $noEnumerate = $true
        if ($enumVal -eq 0) {
            $enumVal.ToString()
        }
        else {
            foreach ($flag in [Enum]::GetValues($EnumType)) {
                if ($flag -eq 0) {
                    continue
                }

                if ($enumVal.HasFlag($flag)) {
                    $flag.ToString()
                    $newVal = ($enumVal -as $rawType) -band -bnot ($flag)
                    $enumVal = [Enum]::ToObject($EnumType, $newVal)
                }

                if ($enumVal -eq 0) {
                    break
                }
            }

            # Check for any remaining bits that don't correspond to defined flags.
            if ($enumVal) {
                "0x$($enumVal.ToString('X'))"
            }
        }
    }
    else {
        $noEnumerate = $false
        $enumVal.ToString()
    }

    $parsedStrings = @(
        $rawStrings | ForEach-Object {
            $val = $_
            if ($Prefix -and $val -like "$Prefix*") {
                $val = $val.Substring($Prefix.Length)
            }

            $val.ToLowerInvariant()
        }
    )

    Write-Output -InputObject $parsedStrings -NoEnumerate:$noEnumerate
}


filter Format-DateTime {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory, ValueFromPipeline)]
        [AllowEmptyString()]
        [string]$InputObject
    )

    if ([string]::IsNullOrWhiteSpace($InputObject)) {
        return $null
    }

    [string[]]$formats = @(
        "yyyy-MM-ddTHH:mm:ss"
        "yyyy-MM-ddTHH:mm:ssZ"
        "yyyy-MM-ddTHH:mm:sszzz"
    )
    $styles = [DateTimeStyles]'AllowWhiteSpaces, AssumeLocal, AdjustToUniversal'

    $dt = [DateTime]0
    if ([DateTime]::TryParseExact($InputObject, $formats, [CultureInfo]::InvariantCulture, $styles, [ref]$dt)) {
        $dt.ToString("o", [CultureInfo]::InvariantCulture)
    }
    else {
        # If it fails we just return the original string.
        $InputObject
    }
}

filter Format-DaysOfMonth {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory, ValueFromPipeline)]
        [int]
        $InputObject
    )


    , @(
        # No days selected should result in an empty array.
        if ($InputObject -ne 0) {
            for ($i = 0; $i -lt 31; $i++) {
                $val = 1 -shl $i
                if ($InputObject -band $val) {
                    $i + 1
                }
            }

            if ($InputObject -band 0x80000000) {
                "last"
            }
        }
    )
}

filter Format-WeeksOfMonth {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory, ValueFromPipeline)]
        [int]
        $InputObject
    )

    , @(
        # No weeks selected should result in an empty array.
        if ($InputObject -ne 0) {
            for ($i = 0; $i -lt 4; $i++) {
                $val = 1 -shl $i
                if ($InputObject -band $val) {
                    $i + 1
                }
            }
        }
    )
}

filter Format-MonthsOfYear {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory, ValueFromPipeline)]
        [int]
        $InputObject
    )

    , @(
        # No months selected should result in an empty array.
        if ($InputObject -ne 0) {
            for ($i = 0; $i -lt 12; $i++) {
                $val = 1 -shl $i
                if ($InputObject -band $val) {
                    $i + 1
                }
            }
        }
    )
}

filter Format-Username {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory, ValueFromPipeline)]
        [AllowEmptyString()]
        [string]
        $InputObject
    )

    if ([string]::IsNullOrEmpty($InputObject)) {
        return $null
    }

    $parts = $InputObject.Split([char[]]'\', 2)
    if ($parts.Length -eq 1) {
        $ntAccount = [NTAccount]::New($parts[0])
    }
    else {
        $ntAccount = [NTAccount]::New($parts[0], $parts[1])
    }

    try {
        # Try to normalize the user by translating to a SID and back to an NTAccount.
        $sid = $ntAccount.Translate([SecurityIdentifier])
        $sid.Translate([NTAccount]).Value
    }
    catch [IdentityNotMappedException] {
        # If the account can't be translated to a SID, return the original string.
        $InputObject
    }
}

function Get-TaskAction {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        $ActionCollection
    )

    for ($i = 1; $i -le $ActionCollection.Count; $i++) {
        $action = $ActionCollection.Item($i)

        $info = [Ordered]@{
            type = $action.Type | Format-Enum ([TASK_ACTION_TYPE]) TASK_ACTION_
            id = $action.Id
        }

        if ($action.Type -eq [TASK_ACTION_TYPE]::TASK_ACTION_EXEC) {
            $info.command = $action.Path
            $info.arguments = $action.Arguments
            $info.working_directory = $action.WorkingDirectory
        }
        elseif ($action.Type -eq [TASK_ACTION_TYPE]::TASK_ACTION_COM_HANDLER) {
            $info.class_id = $action.ClassId
            $info.data = $action.Data
        }

        $info
    }
}

function Get-TaskPrincipal {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        $Principal
    )

    $principal2 = [Principal2]::new($Principal)
    [ordered]@{
        id = $Principal.Id
        display_name = $Principal.DisplayName
        user_id = $Principal.UserId | Format-Username
        logon_type = $Principal.LogonType | Format-Enum ([TASK_LOGON_TYPE]) TASK_LOGON_
        group_id = $Principal.GroupId | Format-Username
        run_level = $Principal.RunLevel | Format-Enum ([TASK_RUNLEVEL_TYPE]) TASK_RUNLEVEL_
        process_token_sid = $principal2.ProcessTokenSid | Format-Enum ([TASK_PROCESSTOKENSID_TYPE]) TASK_PROCESSTOKENSID_
        required_privileges = @(
            for ($i = 1; $i -le $principal2.RequiredPrivilegeCount; $i++) {
                $principal2.GetRequiredPrivilege($i)
            }
        )
    }
}

function Get-TaskRegistrationInfo {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        $RegistrationInfo
    )

    [Ordered]@{
        author = $RegistrationInfo.Author
        date = $RegistrationInfo.Date
        description = $RegistrationInfo.Description
        documentation = $RegistrationInfo.Documentation
        source = $RegistrationInfo.Source
        uri = $RegistrationInfo.URI
        version = $RegistrationInfo.Version
    }
}

function Get-TaskSetting {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        $Settings
    )

    [Ordered]@{
        allow_demand_start = $Settings.AllowDemandStart
        restart_interval = $Settings.RestartInterval
        restart_count = $Settings.RestartCount
        multiple_instances = $Settings.MultipleInstances | Format-Enum ([TASK_INSTANCES_POLICY]) TASK_INSTANCES_
        stop_if_going_on_batteries = $Settings.StopIfGoingOnBatteries
        disallow_start_if_on_batteries = $Settings.DisallowStartIfOnBatteries
        allow_hard_terminate = $Settings.AllowHardTerminate
        start_when_available = $Settings.StartWhenAvailable
        run_only_if_network_available = $Settings.RunOnlyIfNetworkAvailable
        execution_time_limit = $Settings.ExecutionTimeLimit
        enabled = $Settings.Enabled
        deleted_expired_task_after = $Settings.DeletedExpiredTaskAfter
        priority = $Settings.Priority
        compatibility = $Settings.Compatibility | Format-Enum ([TASK_COMPATIBILITY]) TASK_COMPATIBILITY_
        hidden = $Settings.Hidden
        idle_settings = [Ordered]@{
            idle_duration = $Settings.IdleSettings.IdleDuration
            wait_timeout = $Settings.IdleSettings.WaitTimeout
            stop_on_idle_end = $Settings.IdleSettings.StopOnIdleEnd
            restart_on_idle = $Settings.IdleSettings.RestartOnIdle
        }
        run_only_if_idle = $Settings.RunOnlyIfIdle
        wake_to_run = $Settings.WakeToRun
        network_settings = [Ordered]@{
            name = $Settings.NetworkSettings.Name
            id = $Settings.NetworkSettings.Id
        }
        disallow_start_on_remote_app_session = $Settings.DisallowStartOnRemoteAppSession
        use_unified_scheduling_engine = $Settings.UseUnifiedSchedulingEngine
        maintenance_settings = [Ordered]@{
            period = $Settings.MaintenanceSettings.Period
            deadline = $Settings.MaintenanceSettings.Deadline
            exclusive = $Settings.MaintenanceSettings.Exclusive
        }
        volatile = $Settings.Volatile
    }
}

function Get-TaskTrigger {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        $TriggerCollection
    )

    for ($i = 1; $i -le $TriggerCollection.Count; $i++) {
        $trigger = $TriggerCollection.Item($i)

        $info = [Ordered]@{
            type = $trigger.Type | Format-Enum ([TASK_TRIGGER_TYPE2]) TASK_TRIGGER_
            id = $trigger.Id
            start_boundary = $trigger.StartBoundary | Format-DateTime
            end_boundary = $trigger.EndBoundary | Format-DateTime
            enabled = $trigger.Enabled
            execution_time_limit = $trigger.ExecutionTimeLimit
            repetition = if ($trigger.Repetition) {
                [Ordered]@{
                    interval = $trigger.Repetition.Interval
                    duration = $trigger.Repetition.Duration
                    stop_at_duration_end = $trigger.Repetition.StopAtDurationEnd
                    repeat_count = $trigger.Repetition.RepeatCount
                }
            }
        }

        if ($trigger.Type -eq [TASK_TRIGGER_TYPE2]::TASK_TRIGGER_EVENT) {
            $info.delay = $trigger.Delay
            $info.subscription = $trigger.Subscription
            $info.value_queries = @(
                for ($i = 1; $i -le $trigger.ValueQueries.Count; $i++) {
                    $valueQuery = $trigger.ValueQueries.Item($i)
                    [Ordered]@{
                        name = $valueQuery.Name
                        value = $valueQuery.Value
                    }
                }
            )
        }
        elseif ($trigger.Type -eq [TASK_TRIGGER_TYPE2]::TASK_TRIGGER_TIME) {
            $info.random_delay = $trigger.RandomDelay
        }
        elseif ($trigger.Type -eq [TASK_TRIGGER_TYPE2]::TASK_TRIGGER_DAILY) {
            $info.days_interval = $trigger.DaysInterval
            $info.random_delay = $trigger.RandomDelay
        }
        elseif ($trigger.Type -eq [TASK_TRIGGER_TYPE2]::TASK_TRIGGER_WEEKLY) {
            $info.days_of_week = $trigger.DaysOfWeek | Format-Enum ([TASK_DAYS_OF_WEEK])
            $info.random_delay = $trigger.RandomDelay
            $info.weeks_interval = $trigger.WeeksInterval
        }
        elseif ($trigger.Type -eq [TASK_TRIGGER_TYPE2]::TASK_TRIGGER_MONTHLY) {
            $info.days_of_month = $trigger.DaysOfMonth | Format-DaysOfMonth
            $info.months_of_year = $trigger.MonthsOfYear | Format-MonthsOfYear
            $info.random_delay = $trigger.RandomDelay
            $info.run_on_last_day_of_month = $trigger.RunOnLastDayOfMonth
        }
        elseif ($trigger.Type -eq [TASK_TRIGGER_TYPE2]::TASK_TRIGGER_MONTHLYDOW) {
            $info.days_of_week = $trigger.DaysOfWeek | Format-Enum ([TASK_DAYS_OF_WEEK])
            $info.months_of_year = $trigger.MonthsOfYear | Format-MonthsOfYear
            $info.random_delay = $trigger.RandomDelay
            $info.run_on_last_week_of_month = $trigger.RunOnLastWeekOfMonth
            $info.weeks_of_month = $trigger.WeeksOfMonth | Format-WeeksOfMonth
        }
        elseif ($trigger.Type -eq [TASK_TRIGGER_TYPE2]::TASK_TRIGGER_IDLE) {
            # No props to add for idle trigger.
        }
        elseif ($trigger.Type -eq [TASK_TRIGGER_TYPE2]::TASK_TRIGGER_REGISTRATION) {
            $info.delay = $trigger.Delay
        }
        elseif ($trigger.Type -eq [TASK_TRIGGER_TYPE2]::TASK_TRIGGER_BOOT) {
            $info.delay = $trigger.Delay
        }
        elseif ($trigger.Type -eq [TASK_TRIGGER_TYPE2]::TASK_TRIGGER_LOGON) {
            $info.delay = $trigger.Delay
            $info.user_id = $trigger.UserId | Format-Username
        }
        elseif ($trigger.Type -eq [TASK_TRIGGER_TYPE2]::TASK_TRIGGER_SESSION_STATE_CHANGE) {
            $info.delay = $trigger.Delay
            $info.state_change = $trigger.StateChange | Format-Enum ([TASK_SESSION_STATE_CHANGE_TYPE]) TASK_
            $info.user_id = $trigger.UserId | Format-Username
        }

        $info
    }
}

$spec = @{
    options = @{
        name = @{ type = "str" }
        path = @{ type = "str"; default = "\" }
    }
    supports_check_mode = $true
}

$module = [Ansible.Basic.AnsibleModule]::Create($args, $spec)

$module.Result.folder_exists = $false
$module.Result.tasks = @()

$service = New-Object -ComObject Schedule.Service
$service.Connect()

try {
    $folder = $service.GetFolder($module.Params.path)
}
catch {
    $folder = $null
}

if ($folder) {
    $module.Result.folder_exists = $true

    $folderTasks = $folder.GetTasks([TASK_ENUM_FLAGS]::TASK_ENUM_HIDDEN)
    $module.Result.tasks = @(
        for ($i = 1; $i -le $folderTasks.Count; $i++) {
            $task = $folderTasks.Item($i)

            if ($module.Params.name -and $task.Name -ne $module.Params.name) {
                continue
            }

            try {
                $definition = $task.Definition

                [Ordered]@{
                    # Registration info
                    name = $task.Name
                    enabled = $task.Enabled
                    last_run_time = $task.LastRunTime.ToUniversalTime().ToString("o", [CultureInfo]::InvariantCulture)
                    last_task_result = $task.LastTaskResult
                    next_run_time = $task.NextRunTime.ToUniversalTime().ToString("o", [CultureInfo]::InvariantCulture)
                    number_of_missed_runs = $task.NumberOfMissedRuns
                    path = $task.Path
                    state = $task.State | Format-Enum ([TASK_STATE]) TASK_STATE_

                    # Definition
                    actions = @(Get-TaskAction $definition.Actions)
                    data = $definition.Data
                    principal = Get-TaskPrincipal $definition.Principal
                    registration_info = Get-TaskRegistrationInfo $definition.RegistrationInfo
                    settings = Get-TaskSetting $definition.Settings
                    triggers = @(Get-TaskTrigger $definition.Triggers)
                }
            }
            catch {
                $module.FailJson("Failed to get definition for task '$($task.Name)': $_", $_)
            }
        }
    )
}

$module.ExitJson()
