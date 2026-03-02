using System;
using System.Runtime.InteropServices;

namespace SCHTasks
{
    public sealed class TaskPrincipal : IDisposable
    {
        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        private delegate int get_ProcessTokenSidType(
            IntPtr instance,
            out int pProcessTokenSidType);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        private delegate int put_ProcessTokenSidType(
            IntPtr instance,
            int processTokenSidType);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        private delegate int get_RequiredPrivilegeCount(
            IntPtr instance,
            out int pCount);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        private delegate int get_RequiredPrivilege(
            IntPtr instance,
            int index,
            out IntPtr pPrivilege);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        private delegate int AddRequiredPrivilege(
            IntPtr instance,
            IntPtr privilege);

        private const string _iid = "248919AE-E345-4A6D-8AEB-E0D3165C904E";

        private readonly object _principal;
        private readonly IntPtr _punk;
        private readonly IntPtr _ppv;

        private IntPtr[] _funcAddrs = new IntPtr[5];
        private get_ProcessTokenSidType _get_ProcessTokenSidTypeDelegate;
        private put_ProcessTokenSidType _put_ProcessTokenSidTypeDelegate;
        private get_RequiredPrivilegeCount _get_RequiredPrivilegeCountDelegate;
        private get_RequiredPrivilege _get_RequiredPrivilegeDelegate;
        private AddRequiredPrivilege _addRequiredPrivilegeDelegate;

        public TaskPrincipal(object principal)
        {
            _principal;

            _punk = Marshal.GetIUnknownForObject(principal);

            Guid iid = new Guid(_iid);
            int res = Marshal.QueryInterface(_punk, ref iid, out _ppv);
            Marshal.ThrowExceptionForHR(res, (IntPtr)-1);  // Only throws on failure

            IntPtr vtable = Marshal.ReadIntPtr(_ppv);
            for (int i = 0; i < _funcAddrs.Length; i++)
            {
                // IDispatch takes up the first 6 slots.
                IntPtr vtableOffset = IntPtr.Add(vtable, IntPtr.Size * (i + 7));
                _funcAddrs[i] = Marshal.ReadIntPtr(vtableOffset);
            }

            _get_ProcessTokenSidTypeDelegate = Marshal.GetDelegateForFunctionPointer<get_ProcessTokenSidType>(
                _funcAddrs[0]);
            _put_ProcessTokenSidTypeDelegate = Marshal.GetDelegateForFunctionPointer<put_ProcessTokenSidType>(
                _funcAddrs[1]);
            _get_RequiredPrivilegeCountDelegate = Marshal.GetDelegateForFunctionPointer<get_RequiredPrivilegeCount>(
                _funcAddrs[2]);
            _get_RequiredPrivilegeDelegate = Marshal.GetDelegateForFunctionPointer<get_RequiredPrivilege>(
                _funcAddrs[3]);
            _addRequiredPrivilegeDelegate = Marshal.GetDelegateForFunctionPointer<AddRequiredPrivilege>(
                _funcAddrs[4]);
        }

        public int ProcessTokenSidType
        {
            get
            {
                int sidType = 0;
                int res = _get_ProcessTokenSidTypeDelegate(_ppv, out sidType);
                Marshal.ThrowExceptionForHR(res, (IntPtr)-1);

                return sidType;
            }
            set
            {
                int res = _set_ProcessTokenSidTypeDelegate(_ppv, value);
                Marshal.ThrowExceptionForHR(res, (IntPtr)-1);
            }
        }

        public void Dispose()
        {
            if (_punk != IntPtr.Zero)
            {
                Marshal.Release(_punk);
                _punk = IntPtr.Zero;
            }
            if (_ppv != IntPtr.Zero)
            {
                Marshal.Release(_ppv);
                _ppv = IntPtr.Zero;
            }

            GC.SuppressFinalize(this);
        }
        ~TaskPrincipal() { Dispose(); }
    }
}
