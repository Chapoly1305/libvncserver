# ScreensharingAgent (24G84)

- Path: `/Volumes/Tools/ScreenSharingWorkspace/Sequoia_15.6_24G84_ScreenSharing/Volumes/MacintoshHD/System/Library/CoreServices/RemoteManagement/ScreensharingAgent.bundle/Contents/MacOS/ScreensharingAgent`

## file
/Volumes/Tools/ScreenSharingWorkspace/Sequoia_15.6_24G84_ScreenSharing/Volumes/MacintoshHD/System/Library/CoreServices/RemoteManagement/ScreensharingAgent.bundle/Contents/MacOS/ScreensharingAgent: Mach-O universal binary with 2 architectures: [x86_64:\012- Mach-O 64-bit x86_64 executable, flags:<NOUNDEFS|DYLDLINK|TWOLEVEL|PIE>] [\012- arm64e (caps: 0x2):\012- Mach-O 64-bit arm64e (caps: PAC00) executable, flags:<NOUNDEFS|DYLDLINK|TWOLEVEL|PIE>]

## otool -L
/Volumes/Tools/ScreenSharingWorkspace/Sequoia_15.6_24G84_ScreenSharing/Volumes/MacintoshHD/System/Library/CoreServices/RemoteManagement/ScreensharingAgent.bundle/Contents/MacOS/ScreensharingAgent:
	/System/Library/Frameworks/CoreMedia.framework/Versions/A/CoreMedia (compatibility version 1.0.0, current version 3235.13.1)
	/System/Library/Frameworks/CoreVideo.framework/Versions/A/CoreVideo (compatibility version 1.2.0, current version 1.5.0)
	/System/Library/Frameworks/ScreenCaptureKit.framework/Versions/A/ScreenCaptureKit (compatibility version 1.0.0, current version 1.0.0)
	/System/Library/Frameworks/AVFoundation.framework/Versions/A/AVFoundation (compatibility version 1.0.0, current version 2.0.0)
	/System/Library/Frameworks/VideoToolbox.framework/Versions/A/VideoToolbox (compatibility version 1.0.0, current version 3235.13.1)
	/System/Library/PrivateFrameworks/TimeSync.framework/Versions/A/TimeSync (compatibility version 1.0.0, current version 1.0.0)
	/System/Library/PrivateFrameworks/AVConference.framework/Versions/A/AVConference (compatibility version 1.0.0, current version 1.0.0)
	/System/Library/PrivateFrameworks/TCC.framework/Versions/A/TCC (compatibility version 1.0.0, current version 1.0.0)
	/System/Library/PrivateFrameworks/SkyLight.framework/Versions/A/SkyLight (compatibility version 64.0.0, current version 600.0.0)
	/System/Library/PrivateFrameworks/UserActivity.framework/Versions/A/UserActivity (compatibility version 1.0.0, current version 551.0.0, weak)
	/System/Library/Frameworks/AppKit.framework/Versions/C/AppKit (compatibility version 45.0.0, current version 2575.70.51)
	/System/Library/PrivateFrameworks/login.framework/Versions/A/login (compatibility version 1.0.0, current version 259.5.1)
	/System/Library/Frameworks/CoreAudio.framework/Versions/A/CoreAudio (compatibility version 1.0.0, current version 1.0.0)
	/System/Library/Frameworks/ApplicationServices.framework/Versions/A/ApplicationServices (compatibility version 1.0.0, current version 65.0.0)
	/System/Library/Frameworks/Foundation.framework/Versions/C/Foundation (compatibility version 300.0.0, current version 3603.0.0)
	/System/Library/Frameworks/CoreFoundation.framework/Versions/A/CoreFoundation (compatibility version 150.0.0, current version 3603.0.0)
	/System/Library/Frameworks/OpenGL.framework/Versions/A/OpenGL (compatibility version 1.0.0, current version 1.0.0)
	/System/Library/PrivateFrameworks/DiagnosticLogCollection.framework/Versions/A/DiagnosticLogCollection (compatibility version 1.0.0, current version 800.0.0, weak)
	/usr/lib/libbsm.0.dylib (compatibility version 1.0.0, current version 1.0.0)
	/usr/lib/libz.1.dylib (compatibility version 1.0.0, current version 1.2.12)
	/System/Library/Frameworks/OpenCL.framework/Versions/A/OpenCL (compatibility version 1.0.0, current version 1.0.0)
	/System/Library/Frameworks/IOSurface.framework/Versions/A/IOSurface (compatibility version 1.0.0, current version 1.0.0)
	/System/Library/Frameworks/Carbon.framework/Versions/A/Carbon (compatibility version 2.0.0, current version 170.0.0)
	/System/Library/Frameworks/IOKit.framework/Versions/A/IOKit (compatibility version 1.0.0, current version 275.0.0)
	/usr/lib/libobjc.A.dylib (compatibility version 1.0.0, current version 228.0.0)
	/usr/lib/libSystem.B.dylib (compatibility version 1.0.0, current version 1351.0.0)
	/System/Library/Frameworks/AVFAudio.framework/Versions/A/AVFAudio (compatibility version 1.0.0, current version 1.0.0)
	/System/Library/Frameworks/CoreGraphics.framework/Versions/A/CoreGraphics (compatibility version 64.0.0, current version 1889.6.1)
	/System/Library/Frameworks/CoreServices.framework/Versions/A/CoreServices (compatibility version 1.0.0, current version 1226.0.0)

## nm -gj (first 400)

/Volumes/Tools/ScreenSharingWorkspace/Sequoia_15.6_24G84_ScreenSharing/Volumes/MacintoshHD/System/Library/CoreServices/RemoteManagement/ScreensharingAgent.bundle/Contents/MacOS/ScreensharingAgent (for architecture x86_64):
_AVCMediaStreamNegotiatorHDRMode
_AVCMediaStreamNegotiatorTransportProtocolType
_AVCMediaStreamNegotiatorVideoHeight
_AVCMediaStreamNegotiatorVideoResolution
_AVCMediaStreamNegotiatorVideoWidth
_CFAbsoluteTimeGetCurrent
_CFAbsoluteTimeGetGregorianDate
_CFArrayAppendValue
_CFArrayContainsValue
_CFArrayCreateMutable
_CFArrayGetCount
_CFArrayGetTypeID
_CFArrayGetValueAtIndex
_CFArrayRemoveValueAtIndex
_CFBooleanGetTypeID
_CFBundleGetIdentifier
_CFBundleGetInfoDictionary
_CFBundleGetMainBundle
_CFDataAppendBytes
_CFDataCreate
_CFDataCreateMutable
_CFDataCreateWithBytesNoCopy
_CFDataGetBytePtr
_CFDataGetLength
_CFDictionaryAddValue
_CFDictionaryCreate
_CFDictionaryCreateMutable
_CFDictionaryGetCount
_CFDictionaryGetKeysAndValues
_CFDictionaryGetTypeID
_CFDictionaryGetValue
_CFDictionaryGetValueIfPresent
_CFDictionaryReplaceValue
_CFDictionarySetValue
_CFEqual
_CFGetTypeID
_CFMachPortCreateRunLoopSource
_CFMachPortCreateWithPort
_CFNotificationCenterAddObserver
_CFNotificationCenterGetDistributedCenter
_CFNotificationCenterPostNotificationWithOptions
_CFNumberCreate
_CFNumberGetTypeID
_CFNumberGetValue
_CFPreferencesCopyValue
_CFRelease
_CFRetain
_CFRunLoopAddSource
_CFRunLoopAddTimer
_CFRunLoopGetCurrent
_CFRunLoopGetMain
_CFRunLoopRun
_CFRunLoopTimerCreate
_CFRunLoopTimerInvalidate
_CFShow
_CFStringCompare
_CFStringCreateCopy
_CFStringCreateExternalRepresentation
_CFStringCreateWithBytes
_CFStringCreateWithCString
_CFStringCreateWithFormat
_CFStringGetCString
_CFStringGetCStringPtr
_CFStringGetLength
_CFStringGetTypeID
_CFStringHasPrefix
_CFTimeZoneCopySystem
_CFURLCreateData
_CFURLCreateWithBytes
_CFURLCreateWithFileSystemPath
_CFURLGetFileSystemRepresentation
_CGBitmapContextCreate
_CGColorSpaceCreateDeviceRGB
_CGColorSpaceRelease
_CGContextDrawImage
_CGContextRelease
_CGDisplayBitsPerPixel
_CGDisplayBounds
_CGDisplayBytesPerRow
_CGDisplayCopyAllDisplayModes
_CGDisplayCopyDisplayMode
_CGDisplayIDToOpenGLDisplayMask
_CGDisplayIsAsleep
_CGDisplayIsInMirrorSet
_CGDisplayModeGetHeight
_CGDisplayModeGetPixelHeight
_CGDisplayModeGetPixelWidth
_CGDisplayModeGetPixelsHigh
_CGDisplayModeGetPixelsWide
_CGDisplayModeGetResolution
_CGDisplayModeGetWidth
_CGDisplayModeRelease
_CGDisplayModelNumber
_CGDisplayPixelsHigh
_CGDisplayPixelsWide
_CGDisplayRegisterReconfigurationCallback
_CGDisplaySetDisplayMode
_CGEnableEventStateCombining
_CGEventCreate
_CGEventCreateKeyboardEvent
_CGEventCreateMouseEvent
_CGEventCreateNextEvent
_CGEventCreateScrollWheelEvent
_CGEventGetDoubleValueField
_CGEventGetFlags
_CGEventGetIntegerValueField
_CGEventGetLocation
_CGEventGetType
_CGEventKeyboardSetUnicodeString
_CGEventPost
_CGEventSetDoubleValueField
_CGEventSetFlags
_CGEventSetIntegerValueField
_CGEventSetLocation
_CGEventSetTimestamp
_CGEventSetType
_CGEventSourceCreate
_CGEventSourceGetSourceStateID
_CGGetActiveDisplayList
_CGImageGetHeight
_CGImageGetWidth
_CGImageRelease
_CGImageRetain
_CGInhibitLocalEvents
_CGLChoosePixelFormat
_CGLClearDrawable
_CGLCreateContext
_CGLDestroyContext
_CGLDestroyPixelFormat
_CGLGetShareGroup
_CGLSetCurrentContext
_CGMainDisplayID
_CGPostKeyboardEvent
_CGRectOffset
_CGSAddWindowsToSpaces
_CGSCopyCurrentSessionDictionary
_CGSCopyDisplayInfoDictionary
_CGSCurrentCursorSeed
_CGSGetCurrentMouseButtonState
_CGSGetDisplayBounds
_CGSGetEventPort
_CGSGetGlobalCursorData
_CGSGetGlobalCursorDataSize
_CGSHWCaptureDesktop
_CGSInhibitLocalEvents
_CGSInitialize
_CGSIsSecureEventInputSet
_CGSMainConnectionID
_CGSMainDisplayID
_CGSRegisterNotifyProc
_CGSReleaseSession
_CGSRemoveHotKey
_CGSSetBackgroundEventMask
_CGSSetLocalEventsSuppressionInterval
_CGSShieldCursor
_CGSShowSpaces
_CGSSpaceCreate
_CGSSpaceDestroy
_CGSSpaceSetAbsoluteLevel
_CGSUnshieldCursor
_CGSessionCopyCurrentDictionary
_CMSampleBufferGetImageBuffer
_CMSampleBufferGetSampleAttachmentsArray
_CMSampleBufferIsValid
_CMTimeMake
_CVPixelBufferGetIOSurface
_CVPixelBufferRelease
_CVPixelBufferRetain
_CoreDockSendNotification
_CoreEndianFlipData
_DLCLogWithLevel
_Gestalt
_HIGetMousePosition
_IOPMAssertionDeclareUserActivity
_IOPMAssertionSetProperty
_IOSurfaceGetBaseAddress
_IOSurfaceGetBytesPerRow
_IOSurfaceGetHeight
_IOSurfaceGetWidth
_IOSurfaceLock
_IOSurfaceUnlock
_LMGetKbdType
_NDR_record
_NSAppearanceNameFunctionRow
_NSDragPboard
_NSFileTypeForHFSTypeCode
_NSImageNameMultipleDocuments
_NSLocalizedDescriptionKey
_OBJC_CLASS_$_AVCAudioStream
_OBJC_CLASS_$_AVCMediaStreamNegotiator
_OBJC_CLASS_$_AVCScreenCapture
_OBJC_CLASS_$_AVCScreenCaptureConfiguration
_OBJC_CLASS_$_AVCVideoStream
_OBJC_CLASS_$_AVSpeechSynthesizer
_OBJC_CLASS_$_AVSpeechUtterance
_OBJC_CLASS_$_NSAppearance
_OBJC_CLASS_$_NSApplication
_OBJC_CLASS_$_NSArray
_OBJC_CLASS_$_NSAutoreleasePool
_OBJC_CLASS_$_NSBitmapImageRep
_OBJC_CLASS_$_NSBundle
_OBJC_CLASS_$_NSButton
_OBJC_CLASS_$_NSColor
_OBJC_CLASS_$_NSConstantIntegerNumber
_OBJC_CLASS_$_NSCustomTouchBarItem
_OBJC_CLASS_$_NSData
_OBJC_CLASS_$_NSDate
_OBJC_CLASS_$_NSDictionary
_OBJC_CLASS_$_NSError
_OBJC_CLASS_$_NSEvent
_OBJC_CLASS_$_NSImage
_OBJC_CLASS_$_NSMutableArray
_OBJC_CLASS_$_NSMutableDictionary
_OBJC_CLASS_$_NSNumber
_OBJC_CLASS_$_NSObject
_OBJC_CLASS_$_NSPasteboard
_OBJC_CLASS_$_NSRecursiveLock
_OBJC_CLASS_$_NSRunLoop
_OBJC_CLASS_$_NSRunningApplication
_OBJC_CLASS_$_NSScreen
_OBJC_CLASS_$_NSString
_OBJC_CLASS_$_NSThread
_OBJC_CLASS_$_NSTouchBar
_OBJC_CLASS_$_NSUUID
_OBJC_CLASS_$_NSValue
_OBJC_CLASS_$_NSWindow
_OBJC_CLASS_$_NSWorkspace
_OBJC_CLASS_$_NSXPCConnection
_OBJC_CLASS_$_NSXPCInterface
_OBJC_CLASS_$_SCContentFilter
_OBJC_CLASS_$_SCShareableContent
_OBJC_CLASS_$_SCStream
_OBJC_CLASS_$_SCStreamConfiguration
_OBJC_CLASS_$_SLVirtualDisplay
_OBJC_CLASS_$_SLVirtualDisplayConfiguration
_OBJC_CLASS_$_SLVirtualDisplayMode
_OBJC_CLASS_$_SLVirtualDisplaySettings
_OBJC_CLASS_$_TSClockManager
_OBJC_CLASS_$_TSgPTPManager
_OBJC_CLASS_$_UASharedPasteboard
_OBJC_METACLASS_$_NSObject
_PasteboardClear
_PasteboardCopyItemFlavorData
_PasteboardCopyItemFlavors
_PasteboardCreate
_PasteboardGetItemCount
_PasteboardGetItemFlavorFlags
_PasteboardGetItemIdentifier
_PasteboardPutItemFlavor
_PasteboardSynchronize
_SACLockScreenImmediate
_SACScreenLockEnabled
_SACScreenSaverIsRunning
_SCStreamFrameInfoDirtyRects
_SCStreamFrameInfoStatus
_SLSDisplayManagerRegisterPowerStateNotificationOptions
_SLSDisplaySetDynamicGeometryEnabled
_TISCopyCurrentKeyboardInputSource
_TISCopyCurrentKeyboardLayoutInputSource
_TISCopyInputSourceRefForInputSourceID
_TISEnableInputSource
_TISGetInputSourceProperty
_TISSelectInputSource
_TSErrorDomain
_TSNullClockIdentifier
_UTGetOSTypeFromString
_UTTypeCopyDeclaration
_UTTypeCopyPreferredTagWithClass
_UTTypeCreatePreferredIdentifierForTag
_UTTypeIsDeclared
_VTCompressionSessionCreate
_VTSessionCopyProperty
_VTSessionSetProperty
__Block_object_assign
__Block_object_dispose
__NSConcreteGlobalBlock
__NSConcreteStackBlock
__NSGetEnviron
__TISCopyParentInputMethodForInputSource
__Unwind_Resume
___CFConstantStringClassReference
___NSArray0__struct
___NSDictionary0__struct
___bzero
___darwin_check_fd_set_overflow
___error
___memcpy_chk
___memset_chk
___objc_personality_v0
___stack_chk_fail
___stack_chk_guard
___strcat_chk
___strlcat_chk
___strlcpy_chk
__dispatch_main_q
__dispatch_source_type_read
__dispatch_source_type_timer
__mh_execute_header
__objc_empty_cache
__os_log_default
__os_log_error_impl
__os_log_impl
__os_nospin_lock_lock
__os_nospin_lock_unlock
__xpc_error_connection_interrupted
__xpc_error_connection_invalid
__xpc_type_dictionary
__xpc_type_error
_asl_free
_asl_new
_asl_open
_asl_set
_asl_set_filter
_asl_vlog
_asprintf
_audit_token_to_au32
_bcmp
_bind
_bootstrap_look_up
_bootstrap_port
_clBuildProgram
_clCreateBuffer
_clCreateCommandQueue
_clCreateContext
_clCreateImage2D
_clCreateImageFromIOSurface2DAPPLE
_clCreateKernel
_clCreateProgramWithSource
_clEnqueueMapBuffer
_clEnqueueNDRangeKernel
_clEnqueueReadImage
_clEnqueueUnmapMemObject
_clEnqueueWriteBuffer
_clGetGLContextInfoAPPLE
_clGetProgramBuildInfo
_clReleaseCommandQueue
_clReleaseContext
_clReleaseEvent
_clReleaseKernel
_clReleaseMemObject
_clReleaseProgram
_clSetKernelArg
_clWaitForEvents
_close
_connect
_deflate
_deflateEnd
_deflateInit2_
_dispatch_activate
_dispatch_after
_dispatch_async
_dispatch_get_global_queue
_dispatch_group_create
_dispatch_group_enter
_dispatch_group_leave
_dispatch_group_wait
_dispatch_once
_dispatch_queue_create
_dispatch_release
_dispatch_resume
_dispatch_semaphore_create
_dispatch_semaphore_signal
_dispatch_semaphore_wait
_dispatch_set_context
_dispatch_source_cancel
_dispatch_source_create
_dispatch_source_set_cancel_handler
_dispatch_source_set_event_handler
_dispatch_source_set_event_handler_f
_dispatch_source_set_timer
_dispatch_sync
_dispatch_time
_dlclose
_dlopen
_dlsym
_exit
_fchmod
_fclose
_fcntl
_fdopen
_fflush
_flock
_fopen
_fprintf
_fputc
_fputs
_fread
_free
_fscanf
_geteuid
_getgid
_getpid
_getpwuid
_getuid
_glFinish
_glGetError
_glPixelStorei
_glReadBuffer

## objc symbols (first 400)
_OBJC_CLASS_$_AVCAudioStream
_OBJC_CLASS_$_AVCMediaStreamNegotiator
_OBJC_CLASS_$_AVCScreenCapture
_OBJC_CLASS_$_AVCScreenCaptureConfiguration
_OBJC_CLASS_$_AVCVideoStream
_OBJC_CLASS_$_AVSpeechSynthesizer
_OBJC_CLASS_$_AVSpeechUtterance
_OBJC_CLASS_$_NSAppearance
_OBJC_CLASS_$_NSApplication
_OBJC_CLASS_$_NSArray
_OBJC_CLASS_$_NSAutoreleasePool
_OBJC_CLASS_$_NSBitmapImageRep
_OBJC_CLASS_$_NSBundle
_OBJC_CLASS_$_NSButton
_OBJC_CLASS_$_NSColor
_OBJC_CLASS_$_NSConstantIntegerNumber
_OBJC_CLASS_$_NSCustomTouchBarItem
_OBJC_CLASS_$_NSData
_OBJC_CLASS_$_NSDate
_OBJC_CLASS_$_NSDictionary
_OBJC_CLASS_$_NSError
_OBJC_CLASS_$_NSEvent
_OBJC_CLASS_$_NSImage
_OBJC_CLASS_$_NSMutableArray
_OBJC_CLASS_$_NSMutableDictionary
_OBJC_CLASS_$_NSNumber
_OBJC_CLASS_$_NSObject
_OBJC_CLASS_$_NSPasteboard
_OBJC_CLASS_$_NSRecursiveLock
_OBJC_CLASS_$_NSRunLoop
_OBJC_CLASS_$_NSRunningApplication
_OBJC_CLASS_$_NSScreen
_OBJC_CLASS_$_NSString
_OBJC_CLASS_$_NSThread
_OBJC_CLASS_$_NSTouchBar
_OBJC_CLASS_$_NSUUID
_OBJC_CLASS_$_NSValue
_OBJC_CLASS_$_NSWindow
_OBJC_CLASS_$_NSWorkspace
_OBJC_CLASS_$_NSXPCConnection
_OBJC_CLASS_$_NSXPCInterface
_OBJC_CLASS_$_SCContentFilter
_OBJC_CLASS_$_SCShareableContent
_OBJC_CLASS_$_SCStream
_OBJC_CLASS_$_SCStreamConfiguration
_OBJC_CLASS_$_SLVirtualDisplay
_OBJC_CLASS_$_SLVirtualDisplayConfiguration
_OBJC_CLASS_$_SLVirtualDisplayMode
_OBJC_CLASS_$_SLVirtualDisplaySettings
_OBJC_CLASS_$_TSClockManager
_OBJC_CLASS_$_TSgPTPManager
_OBJC_CLASS_$_UASharedPasteboard
_OBJC_METACLASS_$_NSObject
_OBJC_CLASS_$_AVCAudioStream
_OBJC_CLASS_$_AVCMediaStreamNegotiator
_OBJC_CLASS_$_AVCScreenCapture
_OBJC_CLASS_$_AVCScreenCaptureConfiguration
_OBJC_CLASS_$_AVCVideoStream
_OBJC_CLASS_$_AVSpeechSynthesizer
_OBJC_CLASS_$_AVSpeechUtterance
_OBJC_CLASS_$_NSAppearance
_OBJC_CLASS_$_NSApplication
_OBJC_CLASS_$_NSArray
_OBJC_CLASS_$_NSAutoreleasePool
_OBJC_CLASS_$_NSBitmapImageRep
_OBJC_CLASS_$_NSBundle
_OBJC_CLASS_$_NSButton
_OBJC_CLASS_$_NSColor
_OBJC_CLASS_$_NSConstantIntegerNumber
_OBJC_CLASS_$_NSCustomTouchBarItem
_OBJC_CLASS_$_NSData
_OBJC_CLASS_$_NSDate
_OBJC_CLASS_$_NSDictionary
_OBJC_CLASS_$_NSError
_OBJC_CLASS_$_NSEvent
_OBJC_CLASS_$_NSImage
_OBJC_CLASS_$_NSMutableArray
_OBJC_CLASS_$_NSMutableDictionary
_OBJC_CLASS_$_NSNumber
_OBJC_CLASS_$_NSObject
_OBJC_CLASS_$_NSPasteboard
_OBJC_CLASS_$_NSRecursiveLock
_OBJC_CLASS_$_NSRunLoop
_OBJC_CLASS_$_NSRunningApplication
_OBJC_CLASS_$_NSScreen
_OBJC_CLASS_$_NSString
_OBJC_CLASS_$_NSThread
_OBJC_CLASS_$_NSTouchBar
_OBJC_CLASS_$_NSUUID
_OBJC_CLASS_$_NSValue
_OBJC_CLASS_$_NSWindow
_OBJC_CLASS_$_NSWorkspace
_OBJC_CLASS_$_NSXPCConnection
_OBJC_CLASS_$_NSXPCInterface
_OBJC_CLASS_$_SCContentFilter
_OBJC_CLASS_$_SCShareableContent
_OBJC_CLASS_$_SCStream
_OBJC_CLASS_$_SCStreamConfiguration
_OBJC_CLASS_$_SLVirtualDisplay
_OBJC_CLASS_$_SLVirtualDisplayConfiguration
_OBJC_CLASS_$_SLVirtualDisplayMode
_OBJC_CLASS_$_SLVirtualDisplaySettings
_OBJC_CLASS_$_TSClockManager
_OBJC_CLASS_$_TSgPTPManager
_OBJC_CLASS_$_UASharedPasteboard
_OBJC_METACLASS_$_NSObject

## high-performance related strings
***ConsoleNotificationHandler kCGSessionLoggedOff
***ConsoleNotificationHandler kCGSessionLoggedOn
-[SSAgentScreenCapture outputVideoEffectDidStartForStream:]
-[SSAgentScreenCapture outputVideoEffectDidStopForStream:]
-[SSAgentScreenCapture stream:didOutputSampleBuffer:ofType:]
-[SSAgentScreenCapture stream:didStopWithError:]
-[SSUDPSender answerForViewer]
-[SSUDPSender createAVCAudioStreamWithRemoteAddress:connectedSocket:audioConfig:avcClientName:]
-[SSUDPSender createAVCVideoStreamWithRemoteAddress:connectedSocket:displayIDToShare:supports60FPS:sendCursor:audioToken:answerNegotiator:videoEncryptionKeyViewerToServer:videoEncryptionKeyServerToViewer:AVCVideoStream:AVCScreenCapture:avcClientName:]
-[SSUDPSender initWithDisplays:hdrFlags:audioOffer:video1Offer:video2Offer:sessionID:]
-[SSUDPSender screenCapture:didStart:withError:]
-[SSUDPSender screenCapture:didStop:withError:]
-[SSUDPSender sendToRemoteAddress:srcAddress:startingUDPPort:audioEncryptionKeyViewerToServer:audioEncryptionKeyServerToViewer:video1EncryptionKeyViewerToServer:video1EncryptionKeyServerToViewer:video2EncryptionKeyViewerToServer:video2EncryptionKeyServerToViewer:sessionID:supports60FPS:sendCursor:avcClientName:]
-[SSUDPSender stream:didGetLastDecodedFrame:]
-[SSUDPSender stream:didPause:error:]
-[SSUDPSender stream:didReceiveDTMFEventWithDigit:]
-[SSUDPSender stream:didReceiveRTCPPackets:]
-[SSUDPSender stream:didResume:error:]
-[SSUDPSender stream:didStart:error:]
-[SSUDPSender stream:didStartSynchronizer:error:]
-[SSUDPSender stream:didUpdateVideoConfiguration:error:]
-[SSUDPSender stream:downlinkQualityDidChange:]
-[SSUDPSender stream:updateInputFrequencyLevel:]
-[SSUDPSender stream:updateOutputFrequencyLevel:]
-[SSUDPSender stream:uplinkQualityDidChange:]
-[SSUDPSender streamDidInterruptionBegin:]
-[SSUDPSender streamDidInterruptionEnd:]
-[SSUDPSender streamDidRTCPTimeOut:]
-[SSUDPSender streamDidRTPTimeOut:]
-[SSUDPSender streamDidServerDie:]
-[SSUDPSender streamDidStop:]
/AppleInternal/Library/BuildRoots/4~B5F7ugDEeiZbHPVcysocfqJC2XSm4cAWWQ4NOTs/Library/Caches/com.apple.xbs/Sources/RemoteDesktop/RFBCommon/HEVCFrameRate.c
/AppleInternal/Library/BuildRoots/4~B5F7ugDEeiZbHPVcysocfqJC2XSm4cAWWQ4NOTs/Library/Caches/com.apple.xbs/Sources/RemoteDesktop/RFBServer/SendFrameBufferOpenCL.c
/AppleInternal/Library/BuildRoots/4~B5F7ugDEeiZbHPVcysocfqJC2XSm4cAWWQ4NOTs/Library/Caches/com.apple.xbs/Sources/RemoteDesktop/ScreensharingAgent/AgentViewer.c
/System/Library/CoreServices/RemoteManagement/AppleVNCServer.bundle/Contents/Support/SSDragHelper.app/Contents/MacOS/SSDragHelper
/System/Library/CoreServices/RemoteManagement/AppleVNCServer.bundle/Contents/Support/Share Screen Request.app/Contents/MacOS/Share Screen Request
/System/Library/Frameworks/Security.framework/Security
2 or more viewers, send list again to the menu extra
@"AVCAudioStream"
@"AVCMediaStreamNegotiator"
@"AVCScreenCapture"
@"AVCVideoStream"
AVCAudioStream %p
AVCAudioStreamDelegate
AVCScreenCaptureDelegate
AVCVideoStreamDelegate
AgentViewer_AllocateAndInit
AgentViewer_FindByID
CGSSessionScreenIsLocked
ConsoleNotificationHandler kCGSessionConsoleConnect
ConsoleNotificationHandler kCGSessionConsoleDisconnect
CopyRectangleFromVirtualFrameBuffer
DisconnectViewer
Get Drag Info for viewer
GetHEVCEncoderMaxSupportedFrameRate
LoginWindowSession
Mission Control err %d
PostMouseEventIntoSession
Pro Mode not currently active
ProMode active - called release
ProMode active - called release due to display change
ProMode not active
Release UDP Streaming viewerID %d 
SAAllocateMultiVariantCodecMemoryBuffers
SADisplayStreamHandler
SASendViewerArrayToMenuExtra
SASendViewerArrayToMenuExtra %ld entries
SAgent_ViewerDisconnected_rpc %d
SCFrameStatusBlank
SCFrameStatusStarted
SCFrameStatusStopped
SCFrameStatusSuspended
SCStreamDelegate
SCStreamMetricCaptureLatencyTime
SCStreamOutput
SSAgent_RemoveViewer_rpc
SSDaemon_DisconnectViewer_rpc failed, %s dest port %d
SSDaemon_DisconnectViewersSilently_rpc failed, %s dest port %d
ScrapConnectionProcessFileTransfer sessionID %d path %s
SecCodeCheckValidity
SecCodeCopyGuestWithAttributes
SecCodeCopyGuestWithAttributes error %d
SendDragInfoToViewer
SendDragInfoToViewer  result %d
SendDragInfoToViewer %d
Set server stream config viewerID %d startingUDPPort %d 
StartEventStreamListener
StartEventStreamListener_block_invoke
Started capture for first display: %u.  videoStream %p screencapture %p 
Started capture for second display: %u  videoStream %p screencapture %p
T@"AVCAudioStream",&,V_audioStream
T@"AVCMediaStreamNegotiator",&,V_audioAnswerNegotiator
T@"AVCMediaStreamNegotiator",&,V_video1AnswerNegotiator
T@"AVCMediaStreamNegotiator",&,V_video2AnswerNegotiator
T@"AVCScreenCapture",&,V_screenCapture
T@"AVCScreenCapture",&,V_screenCapture2
T@"AVCVideoStream",&,V_videoStream
T@"AVCVideoStream",&,V_videoStream2
T@"NSMutableArray",&,V_activeDisplayStreams
T@"NSMutableArray",&,V_displayIDs
T@"NSObject<OS_dispatch_semaphore>",V_firstFrameSemaphore
T@"NSUUID",&,V_mediaStreamSessionID
TB,V_signalFirstFrameSemaphore
TQ,V_totalFrameCount
TQ,V_totalFrameCountWithLatencyInfo
Td,V_maxFrameLatency
Td,V_minFrameLatency
Td,V_totalFrameLatency
Timed out waiting for firstFrameSemaphore
UDP streaming not active
UDP video stream socket close error %s
UUIDString
UpdateViewer
VNC Gst
ViewerNames
ViewerObserveFlags
VirtualFrameBuffer
WriteToStreamSocket
_activeDisplayStreams
_audioStream
_displayIDs
_firstFrameSemaphore
_maxFrameLatency
_mediaStreamSessionID
_minFrameLatency
_signalFirstFrameSemaphore
_totalFrameCount
_totalFrameCountWithLatencyInfo
_totalFrameLatency
_videoStream
_videoStream2
active display stream not found
active media stream ID %d - unable to get viewer info
activeDisplayStreams
addSession:
addStreamOutput:type:sampleHandlerQueue:error:
agent_SSAgent_AddViewer_rpc
agent_SSAgent_AddViewer_rpc %s %d
agent_SSAgent_ReleaseUDPMediaStreaming_rpc
agent_SSAgent_RemoveViewer_rpc
agent_SSAgent_SetControl_rpc
agent_SSAgent_SetServerStreamConfiguration_rpc
agent_SSAgent_SetServerStreamConfiguration_rpc_block_invoke
agent_SSAgent_ViewerDisconnected_rpc
allocate viewer %d
allocate viewer %p
answerForViewer
audio stream: %p   didPause: %d  error: %ld %s
audio stream: %p   didReceiveRTCPPackets: %lu packets
audio stream: %p   didResume: %d  error: %ld %s
audio stream: %p  didStart: %d error: %ld %s
audio stream: %p  didStartSynchronizer: %d error: %ld %s
audio stream: %p didReceiveDTMFEventWithDigit:%c (0x%x)
audio stream: %p updateInputFrequencyLevel  data length %ld
audio stream: %p updateOutputFrequencyLevel  data length %ld
audio streamDidInterruptionBegin: %p
audio streamDidInterruptionEnd: %p
audio streamDidRTPTimeOut: %p
audio streamDidServerDie: %p
audio streamDidStop: %p
audioStream
avc answer audio size %lu  video1 size %lu video2 size %lu
both viewer and server support 60 FPS on stream 1
both viewer and server support 60 FPS on stream 2
call SendViewersToMenuExtra 
closeWaitingProgressForSession:
configure video1 stream
configure video2 stream
control 
control escape
createAVCAudioStreamWithRemoteAddress:connectedSocket:audioConfig:avcClientName:
createAVCVideoStreamWithRemoteAddress:connectedSocket:displayIDToShare:supports60FPS:sendCursor:audioToken:answerNegotiator:videoEncryptionKeyViewerToServer:videoEncryptionKeyServerToViewer:AVCVideoStream:AVCScreenCapture:avcClientName:
created audio stream %p
currentKeyboardSource %s  viewer->lastSetViewerKeyboardSourceInputID %s
displayIDs
do not send viewerlist since at loginwindow
encoder support 60FPS %d videoConfig.framerate %lu
error from create media stream init options (%p):  %s
error from releasing session %d
firstFrameSemaphore
frame
frame rate error on 1 stream %d
frame rate error on two streams %d
frame status not available
framerate
generateMediaStreamConfigurationWithError:
generateMediaStreamInitOptionsWithError:
going to call SSDaemon_Checkin_rpc serverport %d clientport %d sessionID %d onConsoleFlag %d mypid %d  euid %d userName %s loginWindowFlag %d
going to create audio stream
in virtual frame buffer
initWithDisplays:hdrFlags:audioOffer:video1Offer:video2Offer:sessionID:
initWithFrame:
invalid user name for session
kCGSSessionOnConsoleKey
kCGSSessionUserIDKey
kCGSSessionUserNameKey
kCGSessionLoginDoneKey
loginWindowSession
maxFrameLatency
mediaStreamSessionID
minFrameLatency
must specify at least one video stream
no active session
no frame status
no longer at lock screen or login window - send viewer array to menu extra
not a virtual frame buffer
observingLoginWindowSession
outputVideoEffectDidStartForStream:
outputVideoEffectDidStopForStream:
pasteboard data requested from viewer
posted first mouse down for viewer drag
release media stream
release session %d
remote port for audio stream %d
removeSession:
requestActiveSessionStatus:
rightcontrol 
rxCodecType
screen capture frame count %llu latency count %llu min latency %f max latency %f avg latency %f
screenCapture: %p  didStart: %d  error: %ld %s
screenCapture: %p  didStop: %d  error: %ld %s
screenCapture:didStart:withError:
screenCapture:didStop:withError:
send empty drag info to viewer
send viewers again to menu extra
sendToRemoteAddress:srcAddress:startingUDPPort:audioEncryptionKeyViewerToServer:audioEncryptionKeyServerToViewer:video1EncryptionKeyViewerToServer:video1EncryptionKeyServerToViewer:video2EncryptionKeyViewerToServer:video2EncryptionKeyServerToViewer:sessionID:supports60FPS:sendCursor:avcClientName:
sessionID = %s
sessionThatWasOnConsole = %d
set flag that session %s be modified
set gActiveMediaStreamViewerID %d
setActiveDisplayStreams:
setAudioStream:
setBeingControlled
setBeingObserved
setControlledViaAppleID
setDisplayIDs:
setFirstFrameSemaphore:
setFramerate:
setMaxFrameLatency:
setMediaStreamSessionID:
setMinFrameLatency:
setMinimumFrameInterval:
setSignalFirstFrameSemaphore:
setSynchronizationSourceStreamToken:
setTotalFrameCount:
setTotalFrameCountWithLatencyInfo:
setTotalFrameLatency:
setVideoStream2:
setVideoStream:
setViewerNames:
showWaitingProgressForSession:
signalFirstFrameSemaphore
signalled first frame semaphore
source id was likely changed by the user or another viewer
stop %ld active screen capture streams
stop stream %p
stream %p didStopWithError: %s
stream %p outputVideoEffectDidStartForStream
stream %p outputVideoEffectDidStopForStream
stream %p stopped with result %s
stream 1 raw frame rate %f
stream 1 width %u height %u
stream 2 raw frame rate %f
stream 2 width %u height %u
stream1 encode frame rate %f
stream2 encode frame rate %f
stream:didGetLastDecodedFrame:
stream:didOutputSampleBuffer:ofType:
stream:didPause:error:
stream:didReceiveDTMFEventWithDigit:
stream:didReceiveRTCPPackets:
stream:didResume:error:
stream:didStart:error:
stream:didStartSynchronizer:error:
stream:didStopWithError:
stream:didUpdateVideoConfiguration:error:
stream:downlinkQualityDidChange:
stream:updateInputFrequencyLevel:
stream:updateOutputFrequencyLevel:
stream:uplinkQualityDidChange:
streamDidBecomeActive:
streamDidBecomeInactive:
streamDidInterruptionBegin:
streamDidInterruptionEnd:
streamDidRTCPTimeOut:
streamDidRTPTimeOut:
streamDidRecoverFromRTCPTimeOut:
streamDidServerDie:
streamDidStop:
streamToken
tilesPerFrame
totalFrameCount
totalFrameCountWithLatencyInfo
totalFrameLatency
try to re-install display stream
txCodecFeatureListString
txCodecType
unable to add stream output %s
unable to allocate viewer
unable to configure audio stream:  %s
unable to configure stream:  %s
unable to create compression session %d
unable to create display stream
unable to generate media stream init options for audio stream: %s
unable to get AVCScreenCapture for display %d
unable to get audio stream:  %s
unable to get session dictionary
unable to get session dictionary - going to exit
unable to get viewer
unable to locate viewer
unable to start media stream
v24@0:8@"AVCAudioStream"16
v24@0:8@"AVCScreenCapture"16
v24@0:8@"AVCVideoStream"16
v24@0:8@"SCStream"16
v28@0:8@"AVCAudioStream"16c24
v28@0:8@"AVCScreenCapture"16B24
v32@0:8@"AVCAudioStream"16@"NSArray"24
v32@0:8@"AVCAudioStream"16@"NSData"24
v32@0:8@"AVCVideoStream"16@"NSArray"24
v32@0:8@"AVCVideoStream"16@"NSData"24
v32@0:8@"AVCVideoStream"16@"NSDictionary"24
v32@0:8@"SCStream"16@"NSError"24
v36@0:8@"AVCAudioStream"16B24@"NSError"28
v36@0:8@"AVCScreenCapture"16B24@"NSError"28
v36@0:8@"AVCVideoStream"16B24@"NSError"28
v40@0:8@"AVCScreenCapture"16@"AVCScreenCaptureAttributes"24@"NSError"32
v40@0:8@"SCStream"16^{opaqueCMSampleBuffer=}24q32
video didGetLastDecodedFrame: %p  data size %ld
video stream remote port %d
video stream: %p   didPause: %d  error: %ld %s
video stream: %p   didReceiveRTCPPackets: %lu packets
video stream: %p   didResume: %d  error: %ld %s
video stream: %p   didUpdateVideoConfiguration: %d  error: %ld %s
video stream: %p   downlinkQualityDidChange:%s
video stream: %p   uplinkQualityDidChange:%s
video stream: %p  didStart: %d error: %ld %s
video streamDidRTCPTimeOut: %p
video streamDidRTPTimeOut: %p
video streamDidServerDie: %p
video streamDidStop: %p
videoConfig framerate = %ld
videoConfig rxCodecType = %ld
videoConfig tilesPerFrame = %lu
videoConfig txCodecType = %ld
videoConfig videoStreamMode = %ld
videoStream
videoStream2
videoStreamMode
videoconfig txCodecFeatureListString %s
viewer = %p  viewer->udpSender %p
viewer ID set, but not active sender
viewer array size now %ld
viewer did not set keyboard source
viewer set keyboard sourceID %s
viewer source ID was not set locally
viewer->multiVariantInfo.tilesPerRow %d
wait for first frame
