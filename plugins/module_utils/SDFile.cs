using Microsoft.Win32.SafeHandles;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using Ansible.Privilege;
using ansible_collections.ansible.windows.plugins.module_utils.SDBase;

//TypeAccelerator -Name Ansible.Windows.SDFile.SecurityDescriptorFile -TypeName SecurityDescriptorFile

namespace ansible_collections.ansible.windows.plugins.module_utils.SDFile
{
    internal class NativeHelpers
    {
        [Flags]
        internal enum FlagsAndAttributes : uint
        {
            NONE = 0x00000000,
            FILE_ATTRIBUTE_READONLY = 0x00000001,
            FILE_ATTRIBUTE_HIDDEN = 0x00000002,
            FILE_ATTRIBUTE_SYSTEM = 0x00000004,
            FILE_ATTRIBUTE_ARCHIVE = 0x00000020,
            FILE_ATTRIBUTE_NORMAL = 0x00000080,
            FILE_ATTRIBUTE_TEMPORARY = 0x00000100,
            FILE_ATTRIBUTE_OFFLINE = 0x00001000,
            FILE_ATTRIBUTE_ENCRYPTED = 0x00004000,
            FILE_FLAG_OPEN_NO_RECALL = 0x00100000,
            FILE_FLAG_OPEN_REPARSE_POINT = 0x00200000,
            FILE_FLAG_SESSION_AWARE = 0x00800000,
            FILE_FLAG_BACKUP_SEMANTICS = 0x02000000,
            FILE_FLAG_DELETE_ON_CLOSE = 0x04000000,
            FILE_FLAG_SEQUENTIAL_SCAN = 0x08000000,
            FILE_FLAG_RANDOM_ACCESS = 0x10000000,
            FILE_FLAG_NO_BUFFERING = 0x20000000,
            FILE_FLAG_OVERLAPPED = 0x40000000,
            FILE_FLAG_WRITE_THROUGH = 0x80000000,
        }
    }

    internal class NativeMethods
    {
        [DllImport("Kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        public static extern SafeFileHandle CreateFileW(
             [MarshalAs(UnmanagedType.LPWStr)] string lpFileName,
             UInt32 dwDesiredAccess,
             [MarshalAs(UnmanagedType.U4)] FileShare dwShareMode,
             IntPtr lpSecurityAttributes,
             [MarshalAs(UnmanagedType.U4)] FileMode dwCreationDisposition,
             NativeHelpers.FlagsAndAttributes dwFlagsAndAttributes,
             IntPtr hTemplateFile);
    }

    public class SecurityDescriptorFile : SecurityDescriptorBase
    {
        public new static Dictionary<string, int> GetAccessRightMap()
        {
            return Enum.GetNames(typeof(FileSystemRights))
                       .Cast<string>()
                       .ToDictionary(e => e, e => (int)Enum.Parse(typeof(FileSystemRights), e));
        }

        public SecurityDescriptorFile(string path) : base(ResourceType.FileObject)
        {
            using (new PrivilegeEnabler(false, "SeBackupPrivilege", "SeRestorePrivilege", "SeTakeOwnershipPrivilege", "SeSecurityPrivilege"))
            {
                Handle = NativeMethods.CreateFileW(path, RequiredHandleAccess, FileShare.ReadWrite, IntPtr.Zero,
                    FileMode.Open, NativeHelpers.FlagsAndAttributes.FILE_FLAG_BACKUP_SEMANTICS, IntPtr.Zero);
            }

            if (Handle.IsInvalid)
                throw new SDNativeException(String.Format("CreateFile({0}) failed", path));
        }
    }
}