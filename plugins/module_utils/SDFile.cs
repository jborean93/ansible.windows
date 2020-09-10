using Microsoft.Win32.SafeHandles;
using System;
using System.Collections;
using System.Collections.Generic;
using System.Runtime.ConstrainedExecution;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using Ansible.Privilege;
using ansible_collections.ansible.windows.plugins.module_utils.SDBase;

namespace ansible_collections.ansible.windows.plugins.module_utils.SDFile
{
    internal class NativeHelpers
    {

    }

    internal class NativeMethods
    {

    }

    public class SecurityDescriptorFile : SecurityDescriptorBase
    {
        public override Dictionary<string, int> AccessRightMap = Enum.GetValues(typeof(FileSystemRights))
                                                                      .Cast<FileSystemRights>()
                                                                      .ToDictionary(t => t.ToString(), t => (int)t);
        public override SafeHandle Handle = null;
        public override ResourceType ObjectType = ResourceType.FileObject;

        public SecurityDescriptorFile(string path)
        {
            Handle = CreateFile(....);
        }
    }
}