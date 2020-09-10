using Microsoft.Win32.SafeHandles;
using System;
using System.Collections;
using System.Collections.Generic;
using System.Runtime.ConstrainedExecution;
using System.Runtime.InteropServices;
using System.Security.AccessControl;

//TypeAccelerator -Name Ansible.Windows.SDBase.SecurityDescriptorBase -TypeName SecurityDescriptorBase

namespace ansible_collections.ansible.windows.plugins.module_utils.SDBase
{
    internal class NativeHelpers
    {

    }

    internal class NativeMethods
    {
        [DllImport("Advapi32.dll")]
        public static extern Int32 GetSecurityDescriptorLength(
            SafeSecurityDescriptorBuffer pSecurityDescriptor);

        [DllImport("Advapi32.dll", SetLastError = true)]
        public static extern Int32 GetSecurityInfo(
            SafeHandle handle,
            [MarshalAs(UnmanagedType.U4)] ResourceType ObjectType,
            SecurityInformation SecurityInfo,
            out IntPtr ppsidOwner,
            out IntPtr ppsidGroup,
            out IntPtr ppDacl,
            out IntPtr ppSacl,
            out SafeSecurityDescriptorBuffer ppSecurityDescriptor);

        [DllImport("Kernel32.dll")]
        public static extern IntPtr LocalFree(
            IntPtr hMem);

        [DllImport("Advapi32.dll", SetLastError = true)]
        public static extern Int32 SetSecurityInfo(
            SafeHandle handle,
            [MarshalAs(UnmanagedType.U4)] ResourceType ObjectType,
            SecurityInformation SecurityInfo,
            IntPtr psidOwner,
            IntPtr psidGroup,
            IntPtr pDacl,
            IntPtr pSacl);
    }

    internal class SafeMemoryBuffer : SafeHandleZeroOrMinusOneIsInvalid
    {
        public SafeMemoryBuffer(int cb) : base(true)
        {
            base.SetHandle(Marshal.AllocHGlobal(cb));
        }

        [ReliabilityContract(Consistency.WillNotCorruptState, Cer.MayFail)]
        protected override bool ReleaseHandle()
        {
            Marshal.FreeHGlobal(handle);
            return true;
        }
    }

    internal class SafeSecurityDescriptorBuffer : SafeHandleZeroOrMinusOneIsInvalid
    {
        public SafeSecurityDescriptorBuffer() : base(true) { }

        [ReliabilityContract(Consistency.WillNotCorruptState, Cer.MayFail)]
        protected override bool ReleaseHandle()
        {
            return NativeMethods.LocalFree(handle) == IntPtr.Zero;
        }
    }

    [Flags]
    public enum SecurityInformation : uint
    {
        Owner = 0x00000001,
        Group = 0x00000002,
        Dacl = 0x00000004,
        Sacl = 0x00000008,
        Label = 0x00000010,
        Attribute = 0x00000020,
        Scope = 0x00000040,
        ProcessTrustLabel = 0x00000080,
        AccessFilter = 0x00000100,
        Backup = 0x00010000,
        UnprotectedSacl = 0x10000000,
        UnprotectedDacl = 0x20000000,        
        ProtectedSacl = 0x40000000,
        ProtectedDacl = 0x80000000,
    }

    public class SDNativeException : System.ComponentModel.Win32Exception
    {
        private string _msg;

        public SDNativeException(string message) : this(Marshal.GetLastWin32Error(), message) { }
        public SDNativeException(int errorCode, string message) : base(errorCode)
        {
            _msg = String.Format("{0} ({1}, Win32ErrorCode {2} - 0x{2:X8})", message, base.Message, errorCode);
        }

        public override string Message { get { return _msg; } }
        public static explicit operator SDNativeException(string message)
        {
            return new SDNativeException(message);
        }
    }

    public abstract class SecurityDescriptorBase
    {
        public abstract Dictionary<string, int> AccessRightMap;
        public abstract SafeHandle Handle;
        public abstract ResourceType ObjectType;

        public RawSecurityDescriptor GetSecurityInfo(SecurityInformation secInfo)
        {
            SafeSecurityDescriptorBuffer pSecurityDescriptor;
            IntPtr pSidOwner, pSidGroup, pDacl, pSacl = IntPtr.Zero;

            UInt32 res = NativeMethods.GetSecurityInfo(Handle, ObjectType, secInfo,
                out pSidOwner, out pSidGroup, out pSidDacl, out pSidSacl, out pSecurityDescriptor);
            if (res != 0)
                throw new SDNativeException(res, String.Format("GetSecurityInfo({0}) failed", secInfo.ToString()));

            using (pSecurityDescriptor)
            {
                int sdLength = NativeMethods.GetSecurityDescriptorLength(pSecurityDescriptor);
                byte[] sdBytes = new byte[sdLength];
                Marshal.Copy(pSecurityDescriptor.DangerousGetHandle(), sdBytes, 0, sdBytes.Length);

                return new RawSecurityDescriptor(sdBytes, 0);
            }
        }

        public void SetSecurityInfo(RawSecurityDescriptor securityDescriptor, SecurityInformation securityInfo)
        {
            byte[] sdBytes = new byte[securityDescriptor.BinaryLength];
            securityDescriptor.GetBinaryForm(sdBytes, 0);

            using (SafeMemoryBuffer pSecurityDescriptor = new SafeMemoryBuffer(sdBytes.Length))
            {
                Marshal.Copy(sdBytes, 0, pSecurityDescriptor.DangerousGetHandle(), sdBytes.Length);
            }
        }
    }
}