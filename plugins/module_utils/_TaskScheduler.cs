using System;
using System.Runtime.InteropServices;

// See https://learn.microsoft.com/en-au/windows/win32/api/taskschd/
namespace ansible_collections.ansible.windows.plugins.module_utils._TaskScheduler
{
    public enum TASK_ACTION_TYPE
    {
        TASK_ACTION_EXEC = 0,
        TASK_ACTION_COM_HANDLER = 5,
        TASK_ACTION_SEND_EMAIL = 6,
        TASK_ACTION_SHOW_MESSAGE = 7
    }

    public enum TASK_COMPATIBILITY
    {
        TASK_COMPATIBILITY_AT = 0,
        TASK_COMPATIBILITY_V1 = 1,
        TASK_COMPATIBILITY_V2 = 2,  // Vista/2008
        TASK_COMPATIBILITY_V2_1 = 3,  // 7/2008 R2
        TASK_COMPATIBILITY_V2_2 = 4,  // 8/2012
        TASK_COMPATIBILITY_V2_3 = 5,  // 10/2016
        TASK_COMPATIBILITY_V2_4 = 6  // 10/2016 Build 1703 Creators Update
    }

    [Flags]
    public enum TASK_CREATION
    {
        NONE = 0x0,
        TASK_VALIDATE_ONLY = 0x1,
        TASK_CREATE = 0x2,
        TASK_UPDATE = 0x4,
        TASK_CREATE_OR_UPDATE = 0x6,
        TASK_DISABLE = 0x8,
        TASK_DONT_ADD_PRINCIPAL_ACE = 0x10,
        TASK_IGNORE_REGISTRATION_TRIGGERS = 0x20
    }

    [Flags]
    public enum TASK_ENUM_FLAGS
    {
        NONE = 0x0,
        TASK_ENUM_HIDDEN = 0x1
    }

    public enum TASK_INSTANCES_POLICY
    {
        TASK_INSTANCES_PARALLEL = 0,
        TASK_INSTANCES_QUEUE = 1,
        TASK_INSTANCES_IGNORE_NEW = 2,
        TASK_INSTANCES_STOP_EXISTING = 3
    }

    public enum TASK_LOGON_TYPE
    {
        TASK_LOGON_NONE = 0,
        TASK_LOGON_PASSWORD = 1,
        TASK_LOGON_S4U = 2,
        TASK_LOGON_INTERACTIVE_TOKEN = 3,
        TASK_LOGON_GROUP = 4,
        TASK_LOGON_SERVICE_ACCOUNT = 5,
        TASK_LOGON_INTERACTIVE_TOKEN_OR_PASSWORD = 6
    }

    public enum TASK_PROCESSTOKENSID_TYPE
    {
        TASK_PROCESSTOKENSID_NONE = 0,
        TASK_PROCESSTOKENSID_UNRESTRICTED = 1,
        TASK_PROCESSTOKENSID_DEFAULT = 2
    }

    [Flags]
    public enum TASK_RUN_FLAGS
    {
        TASK_RUN_NO_FLAGS = 0x0,
        TASK_RUN_AS_SELF = 0x1,
        TASK_RUN_IGNORE_CONSTRAINTS = 0x2,
        TASK_RUN_USE_SESSION_ID = 0x4,
        TASK_RUN_USER_SID = 0x8
    }

    public enum TASK_RUNLEVEL_TYPE
    {
        TASK_RUNLEVEL_LUA = 0,
        TASK_RUNLEVEL_HIGHEST = 1
    }

    public enum TASK_SESSION_STATE_CHANGE_TYPE
    {
        TASK_CONSOLE_CONNECT = 1,
        TASK_CONSOLE_DISCONNECT = 2,
        TASK_REMOTE_CONNECT = 3,
        TASK_REMOTE_DISCONNECT = 4,
        TASK_SESSION_LOCK = 7,
        TASK_SESSION_UNLOCK = 8
    }

    public enum TASK_STATE
    {
        TASK_STATE_UNKNOWN = 0,
        TASK_STATE_DISABLED = 1,
        TASK_STATE_QUEUED = 2,
        TASK_STATE_READY = 3,
        TASK_STATE_RUNNING = 4
    }

    public enum TASK_TRIGGER_TYPE2
    {
        TASK_TRIGGER_EVENT = 0,
        TASK_TRIGGER_TIME = 1,
        TASK_TRIGGER_DAILY = 2,
        TASK_TRIGGER_WEEKLY = 3,
        TASK_TRIGGER_MONTHLY = 4,
        TASK_TRIGGER_MONTHLYDOW = 5,
        TASK_TRIGGER_IDLE = 6,
        TASK_TRIGGER_REGISTRATION = 7,
        TASK_TRIGGER_BOOT = 8,
        TASK_TRIGGER_LOGON = 9,
        TASK_TRIGGER_SESSION_STATE_CHANGE = 11,
        TASK_TRIGGER_WNF_STATE_CHANGE = 12,  // TASK_TRIGGER_CUSTOM_TRIGGER_01 is the documented enum for this entry
    }

    [Flags]
    public enum TASK_DAYS_OF_WEEK : short
    {
        None = 0x0,
        Sunday = 0x1,
        Monday = 0x2,
        Tuesday = 0x4,
        Wednesday = 0x8,
        Thursday = 0x10,
        Friday = 0x20,
        Saturday = 0x40
    }

    [ComImport, Guid("248919ae-e345-4a6d-8aeb-e0d3165c904e")]
    // This is important, IDispatch fails on .NET 9+ due to some late binding
    // lookup issues. Using dual and it will still be IDipatch but will do
    // early binding based on the definition order.
    // https://github.com/dotnet/runtime/issues/125008
    [InterfaceType(ComInterfaceType.InterfaceIsDual)]
    public interface IPrincipal2
    {
        TASK_PROCESSTOKENSID_TYPE ProcessTokenSidType { get; set; }
        int RequiredPrivilegeCount { get; }
        string GetRequiredPrivilege(int index);
        void AddRequiredPrivilege(string privilege);
    }

    public class Principal2
    {
        private readonly IPrincipal2 _principal;

        public Principal2(object principal)
        {
            _principal = (IPrincipal2)principal;
        }

        public TASK_PROCESSTOKENSID_TYPE ProcessTokenSidType
        {
            get
            {
                return _principal.ProcessTokenSidType;
            }
            set
            {
                _principal.ProcessTokenSidType = value;
            }
        }

        public int RequiredPrivilegeCount
        {
            get
            {
                return _principal.RequiredPrivilegeCount;
            }
        }

        public string GetRequiredPrivilege(int index)
        {
            return _principal.GetRequiredPrivilege(index);
        }

        public void AddRequiredPrivilege(string privilege)
        {
            _principal.AddRequiredPrivilege(privilege);
        }
    }
}
