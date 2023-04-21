---
layout: single
title:  "Research - Hide My IOCTL"
date:   2022-01-06 20:46:55.487948
categories: Windows Kernel
---
# Hide my IOCTL
The goal of this research is to find how we can safely use IOCTL's.
What are the ways someone can monitor me, and what I can do to avoid it?
What is the best method for us to use?
I will try to answer all of these questions in this blog post.

## Small intro to IOCTL's
IOCTL - Input and output control.

A user-mode code can use the function `DeviceIoControl` to send a control code directly to a specified device driver, causing the corresponding device to perform the corresponding operation.

```cpp

BOOL DeviceIoControl(
 [in] HANDLE hDevice,
 [in] DWORD dwIoControlCode,
 [in, optional] LPVOID lpInBuffer,
 [in] DWORD nInBufferSize,
 [out, optional] LPVOID lpOutBuffer,
 [in] DWORD nOutBufferSize,
 [out, optional] LPDWORD lpBytesReturned,
 [in, out, optional] LPOVERLAPPED lpOverlapped
);

```

Within our driver, we need to allocate an IRP with the major function code `IRP_MJ_DEVICE_CONTROL` or `IRP_MJ_INTERNAL_DEVICE_CONTROL` to support the use of IOCTL's.

### Code snippet for enabling IOCTL support

```cpp
extern "C"
NTSTATUS DriverEntry(_In_ PDRIVER_OBJECT DriverObject, _In_ PUNICODE_STRING RegistryPath)
{

UNREFERENCED_PARAMETER(RegistryPath);

DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = myIoctlHandlerFunction;
	
}
```

```cpp
NTSTATUS myIoctlHandlerFunction(PDEVICE_OBJECT, PIRP Irp);
```

You will also need to create a device and a symlink, but there are tons of examples in google, so I am just going to move on.

## Defining the problems of using IOCTL's
So, the problem I am trying to solve is the fact that using IOCTL's is very very exposed.
If I am a legitimate driver my IOCTL communication interface will probably look like that - 

![](https://raw.githubusercontent.com/amitschendel/amitschendel.github.io/master/assets/images/Pasted%20image%2020220118150406.png)

As we can see in "winobj", very exposed, our device object will appear in this list.
So, in the following sections I am going to cover as many methods I could find to hide/monitor/hook IOCTLs.

## Monitor with file system minifilter driver
To start with, an anti virus or any other kernel monitoring software will probebly use a file system minifilter driver.
A fs minifilter allows us to register post and pre operation callbacks on any action related to the file system.
That means the if we send an IOCTL, any fs minifiter can see it.

```cpp
FLT_PREOP_CALLBACK_STATUS FLTAPI PreOperationCreate(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID* CompletionContext
)
{
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(CompletionContext);
    //
    // Pre-create callback to get file info during creation or opening.
    //
    DbgPrint("%wZ\n", &Data->Iopb->TargetFileObject->FileName);

    return FLT_PREOP_SUCCESS_NO_CALLBACK;
}

```

So, before starting to elaborate on the possible methods to hide ourselves, we need to keep that in mind because it will guide us along.

## Device hooking
The first method we are going to discuss on is device hooking.
What if we could use another driver IOCTL communication interface for ourselves?

This method of device hooking is known mostly for viewing/filtering/monitoring other driver communication but I couldn't find any evidence for using it as a "proxy" for communication.

We can use a documented function called `IoAttachDevice` -

```cpp
NTSTATUS IoAttachDevice(
 [in] PDEVICE_OBJECT SourceDevice,
 [in] PUNICODE_STRING TargetDevice,
 [out] PDEVICE_OBJECT *AttachedDevice
);
```

> The **IoAttachDevice** routine attaches the caller's device object to a named target device object so that I/O requests bound for the target device are routed first to the caller.

Under the hood, `IoAttachDevice` is calling `IoAttachDeviceToDeviceStackSafe` -

```cpp
PDEVICE_OBJECT IoAttachDeviceToDeviceStack(
  [in] PDEVICE_OBJECT SourceDevice,
  [in] PDEVICE_OBJECT TargetDevice
);
```

>The **IoAttachDeviceToDeviceStack** routine attaches the caller's device object to the highest device object in the chain and returns a pointer to the previously highest device object.

Here is the implementation from ReactOS -

```cpp
PDEVICE_OBJECT
NTAPI
IopAttachDeviceToDeviceStackSafe(IN PDEVICE_OBJECT SourceDevice,
IN PDEVICE_OBJECT TargetDevice,
OUT PDEVICE_OBJECT *AttachedToDeviceObject OPTIONAL)
{

	PDEVICE_OBJECT AttachedDevice;

	PEXTENDED_DEVOBJ_EXTENSION SourceDeviceExtension;

	/* Get the Attached Device and source extension */

	AttachedDevice = IoGetAttachedDevice(TargetDevice);

	SourceDeviceExtension = IoGetDevObjExtension(SourceDevice);

	ASSERT(SourceDeviceExtension->AttachedTo == NULL);

	/* Make sure that it's in a correct state */

	if ((AttachedDevice->Flags & DO_DEVICE_INITIALIZING) ||

	(IoGetDevObjExtension(AttachedDevice)->ExtensionFlags &

	(DOE_UNLOAD_PENDING |

	DOE_DELETE_PENDING |

	DOE_REMOVE_PENDING |

	DOE_REMOVE_PROCESSED)))
	{
		/* Device was unloading or being removed */
		AttachedDevice = NULL;
	}
	else
	{
		/* Update atached device fields */
		AttachedDevice->AttachedDevice = SourceDevice;
		AttachedDevice->Spare1++;

		/* Update the source with the attached data */
		SourceDevice->StackSize = AttachedDevice->StackSize + 1;
		SourceDevice->AlignmentRequirement = AttachedDevice->AlignmentRequirement;
		SourceDevice->SectorSize = AttachedDevice->SectorSize;

		/* Check for pending start flag */

		if (IoGetDevObjExtension(AttachedDevice)->ExtensionFlags & DOE_START_PENDING)
		{
			/* Propagate */
			IoGetDevObjExtension(SourceDevice)->ExtensionFlags |=DOE_START_PENDING;
		}

		/* Set the attachment in the device extension */
		SourceDeviceExtension->AttachedTo = AttachedDevice;
	}

	/* Return the attached device */
	if (AttachedToDeviceObject)
		*AttachedToDeviceObject = AttachedDevice;
	
	return AttachedDevice;

}
```

It looks like something we can use, each IOCTL being sent to the driver is first going to go through us. We are at the top of the device stack.

### Code example of device hooking
```cpp
NTSTATUS attachToBeep(PDRIVER_OBJECT driverObject)

{

	 PDEVICE_OBJECT myDevice;
	 UNICODE_STRING beepDriver;
	 auto status = STATUS_SUCCESS;

	 status = IoCreateDevice(driverObject, sizeof(PDEVICE_OBJECT), NULL,FILE_DEVICE_UNKNOWN, FILE_DEVICE_SECURE_OPEN, FALSE, &myDevice);

	 if (!NT_SUCCESS(status))
	 {
		return status;
	 }

	 RtlInitUnicodeString(&beepDriver, L"\\Device\\Beep");

	 status = IoAttachDevice(myDevice, &beepDriver, (PDEVICE_OBJECT*)myDevice->DeviceExtension);

	 return status;
}

```

In the above example, I am attaching myself to the beep driver.

We can use this method to use an already exposed IOCTL's to send our data in these IOCTL's and filter them in our driver.

In our driver, we need to define support for IOCTL's.

```cpp
// Define support for all the major functions in order to not dos the target driver.

for(uiIndex = 0; uiIndex < IRP_MJ_MAXIMUM_FUNCTION; uiIndex++)
{

	pDriverObject->MajorFunction[uiIndex] = UnSupportedFunction;
	pDriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = SupportedFunction;

}


NTSTATUS UnSupportedFunction(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{ 

	auto status = STATUS_NOT_SUPPORTED; 

	IoSkipCurrentIrpStackLocation(Irp);
	status = IoCallDriver((PDEVICE_OBJECT)DeviceObject->DeviceExtension, Irp); 

	return status;
}


NTSTATUS SupportedFunction(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{ 

	auto status = STATUS_SUCCESS;

	//Do what we want.

	return status;

}
```

To find a foreign driver IOCTL, we can use some decompiler and look for the MajorFunction array in index 14. Which is `IRP_MJ_DEVICE_CONTROL`.

![](https://raw.githubusercontent.com/amitschendel/amitschendel.github.io/master/assets/images/Pasted%20image%2020220118153545.png)

So, in the above example we could just define support for `IRP_MJ_DEVICE_CONTROL` and check if the data contains magic bytes, if it is, we will handle it and won't pass it on to the next driver, and if it doesn't, we will just pass it on.

Here is a flow chart to simplify the process -

![](https://raw.githubusercontent.com/amitschendel/amitschendel.github.io/master/assets/images/Pasted%20image%2020220119194625.png)

### Monitor device hooking
Let's switch the viewpoint, and think about how can we know if someone is hooking our device?

After some research, I found out that if we look at our device object, we can check the `AttachedDevice` field and see whether it is `NULL` or contains an address of the device object of the attached device. And from there we can take it further and enumerate all drivers on the system, for each one, check the device object for attached devices and print the driver name of the driver that attached himself to our driver.

```cpp
#include <jxy/string.hpp>
#include "nthelp.h"
#include "main.h"

void DriverUnload(PDRIVER_OBJECT DriverObject)
{

	 UNICODE_STRING beepDriver;
	 IoDeleteDevice(DriverObject->DeviceObject);

}

extern "C"
NTSTATUS DriverEntry(
 PDRIVER_OBJECT DriverObject,
 PUNICODE_STRING RegistryPath)
{

 	UNREFERENCED_PARAMETER(RegistryPath);

 	DriverObject->DriverUnload = DriverUnload;
	
	 auto status = STATUS_SUCCESS;
	 ULONG sizeNeeded = 0;

	 status = ZwQuerySystemInformation(SYSTEM_INFORMATION_CLASS::SystemModuleInformation, nullptr, 0, &sizeNeeded);

	 if (status != STATUS_INFO_LENGTH_MISMATCH)
	 {
		 return status;
	 }

	 PRTL_PROCESS_MODULES ModuleInfo;
	 ModuleInfo = (PRTL_PROCESS_MODULES)ExAllocatePoolWithTag(PagedPool, sizeNeeded, DRIVER_TAG);

	 if (!ModuleInfo)
	 {
	 	DbgPrint("\nUnable to allocate memory for module list.\n");
	 	return status;
	 }

	 status = ZwQuerySystemInformation(SYSTEM_INFORMATION_CLASS::SystemModuleInformation, ModuleInfo, sizeNeeded, NULL);

  
	 for (ULONG i = 0; i < ModuleInfo->NumberOfModules; i++)
	 {
		 const auto currentModule = ModuleInfo->Modules[i];
		 String moduleName;
		 const auto name = ((char*)currentModule.FullPathName + currentModule.OffsetToFileName);

		 moduleName.assign(name, strlen(name));

		 if (isDriver(moduleName))
		 {
		 	const auto drvNameWithOutSys = moduleName.substr(0, moduleName.length() - 4);
		 	const auto driverObjectPath = WString(L"\\Driver\\") + convertStringToWstring(drvNameWithOutSys);

		 	DbgPrint("\nCurrent Driver -> %ws\n", driverObjectPath.c_str());

		 	UNICODE_STRING rawDriverObjectPath;
		 	RtlInitUnicodeString(&rawDriverObjectPath, driverObjectPath.c_str());
		 	PVOID driverHandle = nullptr;

		 	status = ObReferenceObjectByName(&rawDriverObjectPath, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, FILE_ALL_ACCESS, *IoDriverObjectType, KernelMode, NULL, &driverHandle);

		 	if (!driverHandle)
		 	{
				DbgPrint("\nThe Driver Name is different\n");
				continue;
		 	}
			 
		 	printDevices((PDRIVER_OBJECT)driverHandle);

		 	}
	 }

  
 return status;
}

  

bool isDriver(const String& moduleName)
{
	 return moduleName.find(".sys") != std::string::npos || moduleName.find(".SYS") != std::string::npos;
}

  

WString convertStringToWstring(const String& str)
{
	 return WString(str.begin(), str.end());
}

  

NTSTATUS printDevices(PDRIVER_OBJECT driverHandle)
{
	 PDEVICE_OBJECT device = nullptr;
	 PDEVICE_OBJECT attachedDevice = nullptr;
	 auto status = STATUS_SUCCESS;

	 device = driverHandle->DeviceObject;

	 if (device)
	 {

	 	attachedDevice = device->AttachedDevice;

		 if (attachedDevice)
		 {

			DbgPrint("\nDriver of attached device -> %wZ\n", attachedDevice->DriverObject->DriverName);

		 }
 	 }

 	return status;
}
```

The above code is just a POC so forgive me for the unclean code.

Also, the correct way to go over all the drivers on the system is by querying the `\\Driver` directory and not by using the `ObReferenceObjectByName` as I did because some drivers just change their `DriverName` property and that won't work in case it happens.

![](https://raw.githubusercontent.com/amitschendel/amitschendel.github.io/master/assets/images/Pasted%20image%2020220118161427.png)

So here I have attached my driver ("stlkrn") to beep and we can see it very clearly.

### Pros & Cons
**Pros:**

- Easy to implement.
- I couldn't find any evidence for that in "winobj".
- Can help bypass some filter drivers, because we look legit in our file system operation.
- AV's doesn't sign on this AttachedDevice field? (Need to verify). 

**Cons:**

- If someone is searching for that method, he will be able to easily find it, as I did in the code example above.
- It doesn't guarantee that we are the top driver. If another driver is attaching his device after we did it, he is going to be on top of us. (It's can be easily solved).

  
In another manner, if we don't want someone to be attached to us, we can just repeatedly check the AttachedDevice field in our device and verify that the value is `NULL`.
In addition, I wrote a filter driver to check if `IoAttachDevice` is triggering something when it is attaching, I wanted to see if it has any interaction with the FILE_OBJECT of the target device, I couldn't find any.

## DKOM - Direct Kernel Object Modifying
A very well-known method, this method says, we are in the kernel we can change any object that we want (besides the objects that KPP guards on).

That means that we can just replace the target driver majorFunction[IRP_MJ_DEVICE_CONTROL] function pointer with our function pointer and that will cause all the ioctls being sent to the target driver to go to us. This method is also called irp hooking.

```cpp
InterlockedExchangePointer((PVOID*)&pTargetDriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL], hookedDeviceIoControl);
```

The problem here is that AVs can just pre-sign the hashes of all the majorFunction array of all the built-in drivers and it will kind of destroy us.

That said, I don't recommend using this method for that kind of abuse.

## Hooking the FILE_OBJECT of the DRIVER_OBJECT
This method was first presented at BlackHat by Bill Demirkapi about a year ago, the main idea behind it was finding a way to hook the device object of a driver without touching the driver or the device.

```cpp
typedef struct _FILE_OBJECT {
  CSHORT                            Type;
  CSHORT                            Size;
  PDEVICE_OBJECT                    DeviceObject;
  PVPB                              Vpb;
  PVOID                             FsContext;
  PVOID                             FsContext2;
  PSECTION_OBJECT_POINTERS          SectionObjectPointer;
  PVOID                             PrivateCacheMap;
  NTSTATUS                          FinalStatus;
  struct _FILE_OBJECT               *RelatedFileObject;
  BOOLEAN                           LockOperation;
  BOOLEAN                           DeletePending;
  BOOLEAN                           ReadAccess;
  BOOLEAN                           WriteAccess;
  BOOLEAN                           DeleteAccess;
  BOOLEAN                           SharedRead;
  BOOLEAN                           SharedWrite;
  BOOLEAN                           SharedDelete;
  ULONG                             Flags;
  UNICODE_STRING                    FileName;
  LARGE_INTEGER                     CurrentByteOffset;
  __volatile ULONG                  Waiters;
  __volatile ULONG                  Busy;
  PVOID                             LastLock;
  KEVENT                            Lock;
  KEVENT                            Event;
  __volatile PIO_COMPLETION_CONTEXT CompletionContext;
  KSPIN_LOCK                        IrpListLock;
  LIST_ENTRY                        IrpList;
  __volatile PVOID                  FileObjectExtension;
} FILE_OBJECT, *PFILE_OBJECT;
```

As we can see inside the FILE_OBJECT struct we have a DeviceObject.
>To device and intermediate drivers, a file object usually represents a device object.

Let's talk a little bit about what happens in the background when an application calls `NtDeviceIoControlFile`. Here is a very high-level overview.

![](https://raw.githubusercontent.com/amitschendel/amitschendel.github.io/master/assets/images/Pasted%20image%2020220125163153.png)

For our purposes, `IoGetRelatedDeviceObject` retrieves the `DeviceObject` member of the `FILE_OBJECT` structure.

![](https://raw.githubusercontent.com/amitschendel/amitschendel.github.io/master/assets/images/Pasted%20image%2020220125163321.png)

The above figure is from the implementation in ReactOS.

>With the device object in hand, the kernel will attempt to dispatch the request via FastIo and otherwise with an Irp passed to `IoCallDriver`. For `IoCallDriver`, the kernel will determine what function to call by looking up the "Major Function Code" specified inside of the Irp within the `MajorFunction` array in the `DRIVER_OBJECT` structure.

```cpp
typedef struct _DRIVER_OBJECT {
  ...
  PDRIVER_DISPATCH   MajorFunction[IRP_MJ_MAXIMUM_FUNCTION + 1];
} DRIVER_OBJECT, *PDRIVER_OBJECT;
```

>The question I asked was, "What's stopping someone from overwriting the `DeviceObject` pointer of the `FILE_OBJECT` structure with their own device?". Well, it turns out, absolutely nothing!
>
>What we can do is create our own fake driver/device object and then replace this `DeviceObject` pointer with our own. We can intercept IOCTL communication by performing the previously mentioned hooking method for `DRIVER_OBJECT`s, except _we would apply the hook to our **own** driver object_, instead of the driver object that can be easily found.

### Practical implementation of FILE_OBJECT hooking
 First, we need to obtain the file object of the target driver.
 We can achieve that by using `ZwQuerySystemInformation` with the `SystemHandleInformation` information class. It will allow us to query every open handle on the system.
 For each handle we will get the following structure:
 ```cpp
typedef struct _SYSTEM_HANDLE {
	ULONG ProcessId;
	BYTE ObjectTypeNumber;
	BYTE Flags;
	USHORT Handle;
	PVOID Object;
	ACCESS_MASK GrantedAccess;
} SYSTEM_HANDLE, *PSYSTEM_HANDLE;
```

>With this information we can determine if a handle is for the target device with the following steps:
>1.  To determine if a handle is for a file object, we can compare the `ObjectTypeNumber` against the known file object type index.
>2.  Once we know that a handle is a file object, we can compare the `DeviceObject` member of the `FILE_OBJECT` structure against the known target device (the target device is the same across different file objects).

Next, we are going to create our own driver object and device object:
```cpp
	//
	// Generate the object attributes for the fake driver object.
	//
	InitializeObjectAttributes(&fakeDriverAttributes,
				   &BaseDeviceObject->DriverObject->DriverName,
				   OBJ_PERMANENT | OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
				   NULL,
				   NULL);

	fakeDriverObjectSize = sizeof(DRIVER_OBJECT) + sizeof(EXTENDED_DRIVER_EXTENSION);

	//
	// Create the fake driver object.
	//
	status = ObCreateObject(KernelMode,
				*IoDriverObjectType,
				&fakeDriverAttributes,
				KernelMode,
				NULL,
				fakeDriverObjectSize,
				0,
				0,
				RCAST<PVOID*>(&fakeDriverObject));
	
	...
	
	//
	// Generate the object attributes for the fake device object.
	//
	InitializeObjectAttributes(&fakeDeviceAttributes,
				   &realDeviceNameHeader->Name,
				   OBJ_KERNEL_HANDLE | OBJ_PERMANENT,
				   NULL,
				   BaseDeviceObject->SecurityDescriptor);

	fakeDeviceObjectSize = sizeof(DEVICE_OBJECT) + sizeof(EXTENDED_DEVOBJ_EXTENSION);

	...
	
	//
	// Create the fake device object.
	//
	status = ObCreateObject(KernelMode,
				*IoDeviceObjectType,
				&fakeDeviceAttributes,
				KernelMode,
				NULL,
				fakeDeviceObjectSize,
				0,
				0,
				RCAST<PVOID*>(&FileObjHook::FakeDeviceObject));
```

>To hook our fake driver object, we can use the same trick I mentioned before and replace the `MajorFunctions` array part of the `DRIVER_OBJECT` structure to point to our hook functions. Keep in mind that this hooking is being performed on _our_ copy of the driver object, not the actual driver object that can easily be found. The final step is to replace the `DeviceObject` member of the `FILE_OBJECT` with our own device.
>
>Now, the file object is hooked, any call to `IoGetRelatedDeviceObject` will return our fake device which `IoCallDriver` will use to call our patched `MajorFunctions` array.

Now, all that is left to do is replace the original driver file object with the fake one we have just created:
```cpp
//
// Atomically hook the device object of the file.
//

oldDeviceObject = RCAST<PDEVICE_OBJECT>(InterlockedExchange64(RCAST<PLONG64>(&FileObject->DeviceObject), RCAST<LONG64>(FileObjHook::FakeDeviceObject)));
```

Cool, after applying the above, each IOCTL is going to be routed to our device.

### Pros & Cons
**Pros** -
- Easy to implement.
- Uses mostly documented objects, so it's reliable.
- Pretty hard to detect unless you specifically looking for it.

**Cons** -
- Memory artifacts.
- Easy to detect if you are looking for it.

## KSE - Kernel Shim Engine
The KSE is an undocumented mechanism that was introduced in Windows 8.1.

-   It can be applied on drivers and devices.
-   Can hook:
	-   Import address table (IAT).
	-   Driver callbacks
		-   DRIVER_OBJCET's DriverUnload, DriverStartIo, etc.
		-   DRIVER_EXTENSION's AddDevice, etc.
	-   I/O request packet (IRP).
-   Applied when the driver is loaded, a great way to ensure persistence :)

Most of its functions start with the "Kse" prefix.
Currently, I found 163 exported functions.
Some of the functions are :
-   KsepEngineInitialize
-   KseRegisterShim
-   KseShimDatabaseOpen
-   KsepResolveShimHooks
-   KsepPoolAllocatePaged
-   KsepGetShimsForDriver 
-   KsepApplyShimsToDriver 

And much more!

The functions aren't defined in any header file but exported, so it's good for us.
Oh, and the best function I have found is - KseKasperskyInitialize.

So, how do we use it you may ask, well we need to do the following steps:

- Create a shim provider (driver).
- Define the hooks and shims structure.
- Register the shim provider in the KSE Engine.
- Define the modules that should use the shim.
	- Either in the registry or in the shim database.
	- The shim DB is an sdb file on disk which we can modify.
	- The shim DB is not signed!
	- The registry overwrites the SDB records, so maybe we can use it.
- Add the correlation between the shim and shim provider in the sdb.
	- Or hijack one already defined.

To register a shim we can use the function -

```cpp
NTSTATUS KseRegisterShimEx( 
	KSE_SHIM *pShim, 
	PVOID ignored, 
	ULONG flags,
	DRIVER_OBJECT *pDrv_Obj
);
```

The shim object is defined -

```cpp
typedef struct _KSE_SHIM { 
_In_ SIZE_T Size;
_In_ PGUID ShimGuid;
_In_ PWCHAR ShimName;
_Out_ PVOID KseCallbackRoutines;
_In_ PVOID ShimmedDriverTargetedNotification;
_In_ PVOID ShimmedDriverUntargetedNotification;
_In_ PVOID HookCollectionsArray; // array of _KSE_HOOK_COLLECTION.
} KSE_SHIM, *PKSE_SHIM; 
```

```cpp
typedef struct _KSE_HOOK_COLLECTION {
 ULONG64 Type; // 0: NT Export, 1: HAL Export, 2: Driver Export, 3: Callback, 4: Last 
PWCHAR ExportDriverName; // If Type == 2
PVOID HookArray; // array of _KSE_HOOK
 } KSE_HOOK_COLLECTION, *PKSE_HOOK_COLLECTION; 
```

```cpp
KSE_HOOK_COLLECTION pCollecArray[2];
pCollecArray[0].Type = 3; // Driver callback 
pCollecArray[0].ExportDriverName = NULL;
pCollecArray[0].HookArray = pHookArray;
pCollecArray[1].Type = 4; // Last entry in array
pCollecArray[1].ExportDriverName = NULL;
pCollecArray[1].HookArray = NULL; 
```

Note that the last entry of the hook array should be invalid.

```cpp
typedef struct _KSE_HOOK { 
_In_ ULONG64 Type; // 0: Function, 1: IRP Callback, 2: Last
union {
	_In_ PCHAR FunctionName; // If Type == 0
	_In_ ULONG64 CallbackId; // If Type == 1 
};

_In_ PVOID HookFunction; 
_Out_ PVOID OriginalFunction;
 } KSE_HOOK, *PKSE_HOOK;
```

```cpp
KSE_HOOK pHookArray[2];
pHookArray[0].Type = 1; // IRP Callback
pHookArray[0].CallbackId = 115; // IRP_MJ_DEVICE_CONTROL 
pHookArray[0].HookFunction = (PVOID)ShimCallbackAddr; pHookArray[0].OriginalFunction = NULL; 
pHookArray[0].Type = 2; // Last entry in array
pHookArray[0].FunctionName = NULL;
pHookArray[0].HookFunction = NULL;
pHookArray[0].OriginalFunction = NULL; 
```

Now, let's associate the shim with a driver -

![](https://raw.githubusercontent.com/amitschendel/amitschendel.github.io/master/assets/images/Pasted%20image%2020220123230654.png)

For associating the shim with the provider we can hijack a shim that is already defined in the SDB - "autofail.sys"
Or we can add a new entry in the SDB.

I will stop here with that, I haven't had the time to dig deeper than that at the time of writing this section so I will leave it open, and hopefully, in the future, I will add a real example.

**Pros** -
- Hard to detect if you are not looking for it.
- It looks kind of legit.
- More?

**Cons** -
- The provider is a driver so we need to sign it.
- More?

Most of the code snnipets are from "@pwissenlit" presentation, link is down below at the sources section.

## Summary
To sum it up I would say that I couldn't find a way to completely hide when using IOCTLs.
Each method has its pros and cons, I hope I  have covered all of the known ways, and if you find any mistake or want to add a method feel free to contact me.
Thank you for reading.

## Sources
 - [Bill Demirkapi - spectre](https://github.com/D4stiny/spectre)
 - [For information on KSE by @pwissenlit](https://blackhoodie.re/assets/archive/Kernel_Shim_Engine_for_fun_-_pwissenlit.pdf)
 - [Alex ionescu lecture on KSE](https://www.youtube.com/watch?v=lZApVkng5S0)